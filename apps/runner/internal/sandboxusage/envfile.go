// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// A sandbox learns its own limits and use from one file, read-only:
// EnvMountPath/EnvFileName. The runner mounts each sandbox's own directory
// there, so no sandbox sees another's, and nothing flows back to the runner.
// The collector rewrites the file on every refresh and after every layer scan.
// It is replaced whole, by rename: a reader never sees half a file, and a
// directory mount (unlike a file mount) shows each new version.
//
// The file is written only while its container runs, and removed before each
// start (ClearEnvFile), so nothing from before a stop is read after it: it is
// missing for up to a refresh interval after every start. A reader should
// treat a missing field as unknown, and judge the numbers by updated_at and
// disk.measured_at. Times are whole seconds.
const (
	EnvMountPath = "/run/0g"
	EnvFileName  = "environment.json"

	// DiskLimitLabel records a sandbox's requested disk, in bytes, on its
	// container. Unless Docker's filesystem is xfs the runner cannot enforce
	// it, and has no other record of it.
	DiskLimitLabel = "ai.0g.sandbox.disk-limit-bytes"

	envSchemaVersion = 1
	// A directory whose sandbox has had no container for this long is
	// removed. A restore creates the container again under the same name.
	orphanEnvDirAge = 10 * time.Minute
)

// environment is the file's content, schema version 1. Fields not known are
// omitted.
type environment struct {
	Version   int        `json:"version"`
	SandboxID string     `json:"sandbox_id"`
	UpdatedAt time.Time  `json:"updated_at"`
	CPU       *envCPU    `json:"cpu,omitempty"`
	Memory    *envMemory `json:"memory,omitempty"`
	Tasks     *envTasks  `json:"tasks,omitempty"`
	Disk      *envDisk   `json:"disk,omitempty"`
}

type envCPU struct {
	LimitCores            float64  `json:"limit_cores,omitempty"`
	UsedSecondsTotal      *float64 `json:"used_seconds_total,omitempty"`
	ThrottledSecondsTotal *float64 `json:"throttled_seconds_total,omitempty"`
}

type envMemory struct {
	LimitBytes    uint64  `json:"limit_bytes,omitempty"`
	UsedBytes     *uint64 `json:"used_bytes,omitempty"`
	OOMKillsTotal *uint64 `json:"oom_kills_total,omitempty"`
}

type envTasks struct {
	Current *uint64 `json:"current,omitempty"`
	Limit   int64   `json:"limit,omitempty"`
}

type envDisk struct {
	LimitBytes int64 `json:"limit_bytes,omitempty"`
	// UsedBytes is the sandbox's own data, as daytona_sandbox_data_bytes:
	// its writable layer plus what it carried over from backups.
	UsedBytes  *int64     `json:"used_bytes,omitempty"`
	MeasuredAt *time.Time `json:"measured_at,omitempty"`
}

// diskLimit reads DiskLimitLabel; 0 when absent or invalid.
func diskLimit(labels map[string]string) int64 {
	v, err := strconv.ParseInt(labels[DiskLimitLabel], 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// DiskLimitLabelValue is the label's value for a disk of the given bytes.
func DiskLimitLabelValue(bytes int64) string {
	return strconv.FormatInt(bytes, 10)
}

// envFor builds a running sandbox's file from a reading and its last layer
// size. c.mu must be held.
func (c *Collector) envFor(id string, r *reading, at time.Time) environment {
	// Whole seconds: finer times would show how long a pass over the other
	// sandboxes on this runner took.
	e := environment{Version: envSchemaVersion, SandboxID: id, UpdatedAt: at.UTC().Truncate(time.Second)}
	cpu, mem, tasks := &envCPU{LimitCores: r.cpuLimitCores}, &envMemory{LimitBytes: r.memoryLimit, OOMKillsTotal: r.oomKills}, &envTasks{Limit: r.pidsLimit}
	if s := r.stats; s != nil {
		used, throttled, memUsed, cur := s.cpuSeconds, s.cpuThrottledSeconds, s.memoryBytes, s.tasks
		cpu.UsedSecondsTotal, cpu.ThrottledSecondsTotal = &used, &throttled
		mem.UsedBytes = &memUsed
		tasks.Current = &cur
	}
	e.CPU, e.Memory, e.Tasks = cpu, mem, tasks
	disk := &envDisk{LimitBytes: r.diskLimit}
	if l, ok := c.layers[id]; ok {
		used, at := l.bytes+l.carried, l.measuredAt.UTC().Truncate(time.Second)
		disk.UsedBytes, disk.MeasuredAt = &used, &at
	}
	e.Disk = disk
	return e
}

// writeEnvFiles writes every running sandbox's file and, when the container
// list is complete (from a refresh), removes the directories of sandboxes
// gone for orphanEnvDirAge.
func (c *Collector) writeEnvFiles(removeOrphans bool) {
	dir := c.cfg.EnvDir
	if dir == "" {
		return
	}
	now := c.cfg.Now()
	c.mu.Lock()
	envs := make([]environment, 0, len(c.sandboxes))
	known := make(map[string]bool, len(c.sandboxes))
	for id, r := range c.sandboxes {
		known[id] = true
		if r.running && validEnvName(id) {
			envs = append(envs, c.envFor(id, r, now))
		}
	}
	c.mu.Unlock()

	for _, e := range envs {
		if err := writeEnvFile(filepath.Join(dir, e.SandboxID), e); err != nil {
			c.log.Warn("sandbox usage: write environment file", "sandbox", e.SandboxID, "error", err)
		}
	}
	if !removeOrphans {
		return
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return // no sandbox has run yet
	}
	if err != nil {
		c.log.Warn("sandbox usage: list environment directories", "error", err)
		return
	}
	for _, ent := range entries {
		if known[ent.Name()] || !ent.IsDir() || !validEnvName(ent.Name()) {
			continue
		}
		if info, err := ent.Info(); err != nil || now.Sub(info.ModTime()) < orphanEnvDirAge {
			continue
		}
		// The file, then the directory only if that leaves it empty: whatever
		// else a misconfigured EnvDir holds is not the runner's to delete.
		sub := filepath.Join(dir, ent.Name())
		if err := os.Remove(filepath.Join(sub, EnvFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			c.log.Warn("sandbox usage: remove environment file", "sandbox", ent.Name(), "error", err)
			continue
		}
		if err := os.Remove(sub); err != nil {
			c.log.Debug("sandbox usage: keep environment directory", "sandbox", ent.Name(), "error", err)
		}
	}
}

// ClearEnvFile removes a sandbox's file before its container starts. The
// collector writes the file only while the container runs, so it still holds
// what it held at the sandbox's last run, which its program must not take as
// current. With no file a reader knows nothing until the next refresh.
func ClearEnvFile(envDir, sandboxID string) error {
	if envDir == "" || !validEnvName(sandboxID) {
		return nil
	}
	if err := os.Remove(filepath.Join(envDir, sandboxID, EnvFileName)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeEnvFile replaces dir/EnvFileName with e, by rename.
func writeEnvFile(dir string, e environment) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+EnvFileName+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil { // readable by a sandbox's non-root user
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, EnvFileName))
}

// validEnvName guards the paths built from container names. Docker allows
// only [a-zA-Z0-9][a-zA-Z0-9_.-]* in a name; anything else is not used.
func validEnvName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for i, ch := range name {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case i > 0 && (ch == '_' || ch == '.' || ch == '-'):
		default:
			return false
		}
	}
	return true
}

// EnvBind is the bind that mounts a sandbox's directory under envDir at
// EnvMountPath, read-only; "" when envDir is "" or the ID is unusable.
func EnvBind(envDir, sandboxID string) string {
	if envDir == "" || !validEnvName(sandboxID) {
		return ""
	}
	return filepath.Join(envDir, sandboxID) + ":" + EnvMountPath + ":ro"
}

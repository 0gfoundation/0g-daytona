// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
)

// withEnvDir gives the fixture an environment directory and records a 10 GiB
// disk on the running sandbox's container.
func withEnvDir(t *testing.T, f *fixture) string {
	t.Helper()
	dir := t.TempDir()
	f.c.cfg.EnvDir = dir
	c1 := f.docker.inspect["c1"]
	c1.Config = &container.Config{Labels: map[string]string{DiskLimitLabel: DiskLimitLabelValue(10 * gib)}}
	f.docker.inspect["c1"] = c1
	return dir
}

func readEnv(t *testing.T, dir, id string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id, EnvFileName))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return m
}

func TestEnvFile_RunningSandboxSeesItsOwnLimitsAndUse(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	f.now = f.now.Add(123456789 * time.Nanosecond) // the file shows whole seconds
	f.c.refresh(context.Background())
	f.c.scanLayers(context.Background())
	second := f.now.Truncate(time.Second)

	e := readEnv(t, dir, "sb-run")
	b, _ := json.Marshal(e)
	var got environment
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.SandboxID != "sb-run" || !got.UpdatedAt.Equal(second) {
		t.Errorf("header = %d %q %v", got.Version, got.SandboxID, got.UpdatedAt)
	}
	if c := got.CPU; c == nil || c.LimitCores != 2 || *c.UsedSecondsTotal != 12.5 || *c.ThrottledSecondsTotal != 3 {
		t.Errorf("cpu = %+v", c)
	}
	if m := got.Memory; m == nil || m.LimitBytes != 4*gib || *m.UsedBytes != 200<<20 || *m.OOMKillsTotal != 2 {
		t.Errorf("memory = %+v", m)
	}
	if k := got.Tasks; k == nil || *k.Current != 37 || k.Limit != 4096 {
		t.Errorf("tasks = %+v", k)
	}
	if d := got.Disk; d == nil || d.LimitBytes != 10*gib || *d.UsedBytes != 7*gib || !d.MeasuredAt.Equal(second) {
		t.Errorf("disk = %+v", d)
	}

	info, err := os.Stat(filepath.Join(dir, "sb-run", EnvFileName))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("file mode = %v, %v; want 0644 so a non-root user can read it", info, err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "sb-run")); len(entries) != 1 {
		t.Errorf("directory holds %d entries, want the file alone (no temporary files left)", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, "sb-stop")); !os.IsNotExist(err) {
		t.Errorf("a stopped sandbox's file was written: %v", err)
	}
}

// Before the first layer scan the file has the limits, and no disk use.
func TestEnvFile_DiskUseOnlyOnceMeasured(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	f.c.refresh(context.Background())
	disk, _ := readEnv(t, dir, "sb-run")["disk"].(map[string]any)
	if disk == nil || disk["limit_bytes"] != float64(10*gib) || disk["used_bytes"] != nil || disk["measured_at"] != nil {
		t.Errorf("disk before a scan = %v", disk)
	}
}

// Without EnvDir nothing is written, not even relative to the working
// directory.
func TestEnvFile_OffWithoutDir(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	f := newFixture(t)
	f.c.refresh(context.Background())
	f.c.scanLayers(context.Background())
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Errorf("wrote %d entries into the working directory", len(entries))
	}
}

// A sandbox's directory goes once it has had no container for a while; one
// still listed, or gone only briefly (an archive about to be restored), stays.
// Only the file and an emptied directory are removed: anything else in a
// misconfigured EnvDir stays.
func TestEnvFile_OrphanDirectoriesRemovedAfterAWhile(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	for _, id := range []string{"sb-gone", "sb-gone-file", "sb-foreign", "sb-brief", "sb-stop"} {
		if err := os.MkdirAll(filepath.Join(dir, id), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"sb-gone-file/" + EnvFileName, "sb-foreign/" + EnvFileName, "sb-foreign/data"} {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	for _, id := range []string{"sb-gone", "sb-gone-file", "sb-foreign", "sb-stop"} {
		if err := os.Chtimes(filepath.Join(dir, id), old, old); err != nil {
			t.Fatal(err)
		}
	}
	f.now = time.Now()
	f.c.refresh(context.Background())
	for p, want := range map[string]bool{
		"sb-gone": false, "sb-gone-file": false, "sb-brief": true, "sb-stop": true, "sb-run": true,
		"sb-foreign/data": true, "sb-foreign/" + EnvFileName: false,
	} {
		_, err := os.Stat(filepath.Join(dir, p))
		if exists := err == nil; exists != want {
			t.Errorf("%s exists = %v, want %v", p, exists, want)
		}
	}
}

// Before a start the last run's file goes, so its program never reads it as
// current; the directory, which the container mounts, stays.
func TestClearEnvFile(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	f.c.refresh(context.Background())
	if err := ClearEnvFile(dir, "sb-run"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sb-run", EnvFileName)); !os.IsNotExist(err) {
		t.Errorf("file still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sb-run")); err != nil {
		t.Errorf("directory removed: %v", err)
	}
	for _, c := range []struct{ dir, id string }{{dir, "sb-run"}, {dir, "never-ran"}, {dir, "../x"}, {"", "sb-run"}} {
		if err := ClearEnvFile(c.dir, c.id); err != nil {
			t.Errorf("ClearEnvFile(%q, %q) = %v, want nothing to do", c.dir, c.id, err)
		}
	}
}

func TestEnvBind(t *testing.T) {
	if got := EnvBind("/var/lib/env", "0b9a-4f1e"); got != "/var/lib/env/0b9a-4f1e:/run/0g:ro" {
		t.Errorf("EnvBind = %q", got)
	}
	for _, id := range []string{"", "..", "../x", "a/b", ".hidden", "-x", "a b", "a:b"} {
		if got := EnvBind("/var/lib/env", id); got != "" {
			t.Errorf("EnvBind(%q) = %q, want none", id, got)
		}
	}
	if got := EnvBind("", "sb-1"); got != "" {
		t.Errorf("EnvBind without a directory = %q, want none", got)
	}
}

func TestDiskLimit(t *testing.T) {
	for v, want := range map[string]int64{"": 0, "abc": 0, "-1": 0, "12abc": 0, "3221225472": 3 * gib} {
		if got := diskLimit(map[string]string{DiskLimitLabel: v}); got != want {
			t.Errorf("diskLimit(%q) = %d, want %d", v, got, want)
		}
	}
	if DiskLimitLabelValue(3*gib) != "3221225472" {
		t.Errorf("DiskLimitLabelValue = %q", DiskLimitLabelValue(3*gib))
	}
}

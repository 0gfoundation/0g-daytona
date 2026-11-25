// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/prometheus/client_golang/prometheus"
)

const gib = 1 << 30

type fakeDocker struct {
	mu      sync.Mutex
	list    []container.Summary
	inspect map[string]container.InspectResponse // by container ID, without size
	sizes   map[string]int64                     // writable layer by container ID; missing → error
	labels  map[string]map[string]string         // image labels by container ID
	stats   map[string]container.StatsResponse
}

func (f *fakeDocker) ContainerList(context.Context, container.ListOptions) ([]container.Summary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]container.Summary(nil), f.list...), nil
}

func (f *fakeDocker) ContainerInspectWithRaw(_ context.Context, id string, getSize bool) (container.InspectResponse, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if getSize {
		s, ok := f.sizes[id]
		if !ok {
			return container.InspectResponse{}, nil, errors.New("size unavailable")
		}
		return container.InspectResponse{ContainerJSONBase: &container.ContainerJSONBase{ID: id, SizeRw: &s},
			Config: &container.Config{Labels: f.labels[id]}}, nil, nil
	}
	r, ok := f.inspect[id]
	if !ok {
		return container.InspectResponse{}, nil, errors.New("no such container")
	}
	return r, nil, nil
}

func (f *fakeDocker) ContainerStatsOneShot(_ context.Context, id string) (container.StatsResponseReader, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.stats[id]
	if !ok {
		return container.StatsResponseReader{}, errors.New("no stats")
	}
	b, _ := json.Marshal(st)
	return container.StatsResponseReader{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

type fixture struct {
	docker *fakeDocker
	used   uint64 // Docker volume used bytes
	now    time.Time
	c      *Collector
}

// newFixture: sandbox sb-run is running (container c1, 2 CPU, 4 GiB, 4096
// tasks, 2 OOM kills); sb-stop exists but is stopped (container c2).
func newFixture(t *testing.T) *fixture {
	t.Helper()
	procRoot, cgroupRoot := t.TempDir(), t.TempDir()
	write := func(path, content string) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(procRoot, "4242", "cgroup"), "0::/docker/c1\n")
	write(filepath.Join(cgroupRoot, "docker", "c1", "memory.events"), "low 0\nhigh 0\nmax 5\noom 2\noom_kill 2\n")

	pids := int64(4096)
	f := &fixture{
		docker: &fakeDocker{
			list: []container.Summary{
				{ID: "c1", Names: []string{"/sb-run"}, State: container.StateRunning},
				{ID: "c2", Names: []string{"/sb-stop"}, State: container.StateExited},
			},
			inspect: map[string]container.InspectResponse{
				"c1": {ContainerJSONBase: &container.ContainerJSONBase{
					ID:    "c1",
					State: &container.State{Running: true, Pid: 4242},
					HostConfig: &container.HostConfig{Resources: container.Resources{
						CPUPeriod: 100000, CPUQuota: 200000, Memory: 4 * gib, MemorySwap: 4 * gib, PidsLimit: &pids,
					}},
				}},
			},
			sizes: map[string]int64{"c1": 7 * gib, "c2": 11 * gib},
			// c2 was restored from a backup that recorded 5 GiB of its data.
			labels: map[string]map[string]string{"c2": {DataBytesLabel: "5368709120"}},
			stats: map[string]container.StatsResponse{
				"c1": {
					Read: time.Unix(1_800_000_000, 0),
					CPUStats: container.CPUStats{
						CPUUsage:       container.CPUUsage{TotalUsage: 12_500_000_000},
						ThrottlingData: container.ThrottlingData{ThrottledTime: 3_000_000_000},
					},
					MemoryStats: container.MemoryStats{Usage: 300 << 20, Stats: map[string]uint64{"inactive_file": 100 << 20}},
					PidsStats:   container.PidsStats{Current: 37},
					Networks:    map[string]container.NetworkStats{"eth0": {RxBytes: 1000, TxBytes: 2000}},
				},
			},
		},
		used: 63 * gib,
		now:  time.Unix(1_800_000_000, 0),
	}
	f.c = New(Config{
		Docker:                f.docker,
		LayerScanTriggerBytes: 2 * gib,
		ProcRoot:              procRoot,
		CgroupRoot:            cgroupRoot,
		VolumeUsage: func(context.Context, string) (uint64, uint64, uint64, error) {
			return 500 * gib, f.used, 400 * gib, nil
		},
		Now: func() time.Time { return f.now },
	})
	return f
}

// values gathers the collector's output as "name{sandbox_id}" → value, and
// fails if any metric carries a label other than sandbox_id.
func values(t *testing.T, c *Collector) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range m.GetLabel() {
				if l.GetName() != "sandbox_id" {
					t.Errorf("%s carries label %q: only the sandbox ID may leave the runner", mf.GetName(), l.GetName())
				}
				key += "{" + l.GetValue() + "}"
			}
			switch {
			case m.Gauge != nil:
				out[key] = m.GetGauge().GetValue()
			case m.Counter != nil:
				out[key] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

func TestCollect_RunningAndStoppedSandboxes(t *testing.T) {
	f := newFixture(t)
	f.c.refresh(context.Background())
	f.c.scanLayers(context.Background())
	got := values(t, f.c)

	want := map[string]float64{
		"daytona_sandbox_running{sb-run}":                                    1,
		"daytona_sandbox_running{sb-stop}":                                   0,
		"daytona_sandbox_cpu_seconds_total{sb-run}":                          12.5,
		"daytona_sandbox_cpu_throttled_seconds_total{sb-run}":                3,
		"daytona_sandbox_cpu_limit_cores{sb-run}":                            2,
		"daytona_sandbox_memory_bytes{sb-run}":                               200 << 20,
		"daytona_sandbox_memory_limit_bytes{sb-run}":                         4 * gib,
		"daytona_sandbox_oom_kills_total{sb-run}":                            2,
		"daytona_sandbox_tasks{sb-run}":                                      37,
		"daytona_sandbox_tasks_limit{sb-run}":                                4096,
		"daytona_sandbox_network_receive_bytes_total{sb-run}":                1000,
		"daytona_sandbox_network_transmit_bytes_total{sb-run}":               2000,
		"daytona_sandbox_writable_layer_bytes{sb-run}":                       7 * gib,
		"daytona_sandbox_writable_layer_bytes{sb-stop}":                      11 * gib,
		"daytona_sandbox_data_bytes{sb-run}":                                 7 * gib,
		"daytona_sandbox_data_bytes{sb-stop}":                                16 * gib, // 11 written since the restore + 5 carried
		"daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-run}":  float64(f.now.Unix()),
		"daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-stop}": float64(f.now.Unix()),
		"daytona_runner_docker_volume_size_bytes":                            500 * gib,
		"daytona_runner_docker_volume_used_bytes":                            63 * gib,
		"daytona_runner_docker_volume_available_bytes":                       400 * gib,
		"daytona_sandbox_usage_refreshed_timestamp_seconds":                  float64(f.now.Unix()),
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %v (present %v), want %v", k, g, ok, v)
		}
	}
	if len(got) != len(want) {
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("unexpected metric %s = %v", k, got[k])
			}
		}
	}
}

func TestCollect_RemovedSandboxDisappears(t *testing.T) {
	f := newFixture(t)
	f.c.refresh(context.Background())
	f.c.scanLayers(context.Background())

	f.docker.list = f.docker.list[:1] // sb-stop deleted
	f.c.refresh(context.Background())
	for k := range values(t, f.c) {
		if bytes.Contains([]byte(k), []byte("sb-stop")) {
			t.Errorf("deleted sandbox still exported: %s", k)
		}
	}
}

func TestRefresh_EarlyLayerScanWhenVolumeGrowsFast(t *testing.T) {
	f := newFixture(t)
	f.c.scanLayers(context.Background()) // baseline: 63 GiB used

	f.used = 64 * gib // +1 GiB, under the 2 GiB trigger
	f.c.refresh(context.Background())
	select {
	case <-f.c.scanNow:
		t.Fatal("early scan requested after 1 GiB of growth")
	default:
	}

	f.used = 65 * gib // +2 GiB since the scan began
	f.c.refresh(context.Background())
	select {
	case <-f.c.scanNow:
	default:
		t.Fatal("no early scan after 2 GiB of growth")
	}
}

func TestRefresh_NoEarlyScanBeforeFirstScan(t *testing.T) {
	f := newFixture(t)
	f.used = 400 * gib
	f.c.refresh(context.Background())
	select {
	case <-f.c.scanNow:
		t.Fatal("early scan requested with no baseline; the first scan runs at start anyway")
	default:
	}
}

func TestLayerScan_KeepsLastSizeWhenSizingFails(t *testing.T) {
	f := newFixture(t)
	f.c.refresh(context.Background())
	f.c.scanLayers(context.Background())
	first := f.now

	f.now = f.now.Add(5 * time.Minute)
	delete(f.docker.sizes, "c1")
	f.docker.sizes["c2"] = 12 * gib
	f.c.scanLayers(context.Background())
	got := values(t, f.c)

	if got["daytona_sandbox_writable_layer_bytes{sb-run}"] != 7*gib ||
		got["daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-run}"] != float64(first.Unix()) {
		t.Errorf("sb-run: want the last size with its old timestamp, got %v at %v",
			got["daytona_sandbox_writable_layer_bytes{sb-run}"], got["daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-run}"])
	}
	if got["daytona_sandbox_writable_layer_bytes{sb-stop}"] != 12*gib ||
		got["daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-stop}"] != float64(f.now.Unix()) {
		t.Errorf("sb-stop: want the new size and timestamp")
	}

	// Docker reports a size it could not take as -1, with no error: not a
	// reading either.
	f.now = f.now.Add(5 * time.Minute)
	f.docker.sizes["c2"] = -1
	f.c.scanLayers(context.Background())
	got = values(t, f.c)
	if got["daytona_sandbox_writable_layer_bytes{sb-stop}"] != 12*gib || got["daytona_sandbox_data_bytes{sb-stop}"] != 17*gib ||
		got["daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-stop}"] != float64(f.now.Add(-5*time.Minute).Unix()) {
		t.Errorf("sb-stop sized -1: want the last size and its timestamp, got layer %v, data %v at %v",
			got["daytona_sandbox_writable_layer_bytes{sb-stop}"], got["daytona_sandbox_data_bytes{sb-stop}"],
			got["daytona_sandbox_writable_layer_measured_timestamp_seconds{sb-stop}"])
	}
}

// A container that stops between the list and its stats call gets an empty
// reading from Docker, not an error.
func TestRefresh_EmptyStatsOmitted(t *testing.T) {
	f := newFixture(t)
	f.docker.stats["c1"] = container.StatsResponse{}
	f.c.refresh(context.Background())
	got := values(t, f.c)
	for _, k := range []string{"daytona_sandbox_cpu_seconds_total{sb-run}", "daytona_sandbox_memory_bytes{sb-run}", "daytona_sandbox_tasks{sb-run}"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s exported from an empty reading", k)
		}
	}
}

func TestRefresh_UnreadableStatsAndCgroupOmitThoseMetrics(t *testing.T) {
	f := newFixture(t)
	delete(f.docker.stats, "c1")
	f.c.cfg.CgroupRoot = t.TempDir() // no memory.events
	f.c.refresh(context.Background())
	got := values(t, f.c)
	for _, k := range []string{"daytona_sandbox_cpu_seconds_total{sb-run}", "daytona_sandbox_memory_bytes{sb-run}", "daytona_sandbox_oom_kills_total{sb-run}"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s exported without a reading", k)
		}
	}
	if got["daytona_sandbox_running{sb-run}"] != 1 || got["daytona_sandbox_memory_limit_bytes{sb-run}"] != 4*gib {
		t.Error("readings that did succeed are missing")
	}
}

func TestCgroupV2Path(t *testing.T) {
	for in, want := range map[string]string{
		"0::/docker/abc\n":                         "/docker/abc",
		"12:pids:/docker/abc\n0::/docker/abc\n":    "/docker/abc",
		"12:pids:/docker/abc\n1:name=systemd:/x\n": "",
		"0::/../../outside\n":                      "",
		"0::\n":                                    "",
	} {
		got, ok := cgroupV2Path(in)
		if got != want || ok != (want != "") {
			t.Errorf("cgroupV2Path(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestKeyedValue(t *testing.T) {
	events := "low 0\nhigh 0\nmax 5\noom 2\noom_kill 7\noom_group_kill 0\n"
	if v, ok := keyedValue(events, "oom_kill"); !ok || v != 7 {
		t.Errorf("oom_kill = %d, %v", v, ok)
	}
	if _, ok := keyedValue(events, "missing"); ok {
		t.Error("missing key reported present")
	}
}

func TestStatsFrom_PageCache(t *testing.T) {
	v1 := statsFrom(container.StatsResponse{MemoryStats: container.MemoryStats{Usage: 500, Stats: map[string]uint64{"total_inactive_file": 200}}})
	if v1.memoryBytes != 300 {
		t.Errorf("cgroup v1 key: got %d, want 300", v1.memoryBytes)
	}
	none := statsFrom(container.StatsResponse{MemoryStats: container.MemoryStats{Usage: 500}})
	if none.memoryBytes != 500 || none.hasNetwork {
		t.Errorf("no page-cache key: got %d, network %v", none.memoryBytes, none.hasNetwork)
	}
}

func TestCarriedBytes(t *testing.T) {
	for in, want := range map[string]int64{
		"": 0, "123": 123, "-5": 0, "x": 0,
		"1125899906842624":    1 << 50, // the bound
		"1125899906842625":    0,       // past it: not a label this runner wrote
		"9223372036854775807": 0,       // would overflow the sums
	} {
		labels := map[string]string{DataBytesLabel: in}
		if in == "" {
			labels = nil
		}
		if got := CarriedBytes(labels); got != want {
			t.Errorf("CarriedBytes(%q) = %d, want %d", in, got, want)
		}
	}
}

// A backup records what the container carried plus its writable layer, so the
// data survives any number of backup and restore rounds.
func TestBackupDataLabel(t *testing.T) {
	if got := BackupDataLabel(nil, 3*gib); got != "LABEL ai.0g.sandbox.data-bytes=3221225472" {
		t.Errorf("first backup: %s", got)
	}
	restored := map[string]string{DataBytesLabel: "3221225472"}
	if got := BackupDataLabel(restored, gib); got != "LABEL ai.0g.sandbox.data-bytes=4294967296" {
		t.Errorf("backup after a restore: %s", got)
	}
	if got := BackupDataLabel(restored, -1); got != "LABEL ai.0g.sandbox.data-bytes=3221225472" {
		t.Errorf("unknown writable layer: %s", got)
	}
	if ClearedDataLabel != "LABEL ai.0g.sandbox.data-bytes=0" {
		t.Errorf("ClearedDataLabel = %s", ClearedDataLabel)
	}
}

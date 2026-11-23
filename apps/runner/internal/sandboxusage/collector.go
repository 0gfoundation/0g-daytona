// SPDX-License-Identifier: AGPL-3.0

// Package sandboxusage measures each sandbox's own resource use and exports it
// on the runner's token-protected /metrics (0g-sandbox#148).
//
// Only numbers leave this package, labelled with the sandbox ID: no process
// names, command lines, file names or network destinations. The operator must
// not see the workload.
//
// CPU, memory, task count, OOM kills and network bytes are cheap to read and
// are refreshed together. A sandbox's writable layer can only be sized by
// walking every file in it, so it is measured on its own, slower schedule, and
// early when the Docker volume grows fast.
package sandboxusage

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shirou/gopsutil/v4/disk"
)

// DockerAPI is the part of the Docker client the collector uses.
type DockerAPI interface {
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
	ContainerInspectWithRaw(ctx context.Context, containerID string, getSize bool) (container.InspectResponse, []byte, error)
	ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error)
}

// VolumeUsageFunc reports the size, used and available bytes of the filesystem
// holding path.
type VolumeUsageFunc func(ctx context.Context, path string) (size, used, available uint64, err error)

type Config struct {
	Logger *slog.Logger
	Docker DockerAPI
	// Interval between readings of CPU, memory, tasks, OOM kills, network and
	// the Docker volume.
	Interval time.Duration
	// LayerScanInterval is how often every sandbox's writable layer is sized.
	LayerScanInterval time.Duration
	// LayerScanTriggerBytes starts a layer scan early once the Docker volume's
	// used bytes have grown by at least this much since the last scan began.
	// 0 disables the early scan.
	LayerScanTriggerBytes uint64

	// DockerRoot is the directory whose filesystem holds the sandboxes'
	// layers. Default /var/lib/docker.
	DockerRoot string
	// ProcRoot and CgroupRoot default to /proc and /sys/fs/cgroup.
	ProcRoot   string
	CgroupRoot string
	// VolumeUsage defaults to statfs through gopsutil.
	VolumeUsage VolumeUsageFunc
	Now         func() time.Time
}

const (
	perContainerTimeout = 10 * time.Second
	// Sizing one layer walks all of its files; a sandbox with millions of
	// small files can take a while, and must not stall the other sandboxes'
	// measurements for long.
	layerSizeTimeout = 2 * time.Minute
	// Early scans triggered by volume growth are at most this frequent.
	minLayerScanGap = time.Minute
)

// Collector implements prometheus.Collector over the latest readings, so a
// scrape never waits for Docker.
type Collector struct {
	cfg     Config
	log     *slog.Logger
	scanNow chan struct{}

	mu             sync.Mutex
	sandboxes      map[string]*reading // by sandbox ID, from the latest refresh
	layers         map[string]layer    // by sandbox ID, from layer scans
	volume         *volume
	refreshedAt    time.Time
	usedAtLastScan uint64
	scanned        bool

	desc descs
}

type reading struct {
	containerID   string
	running       bool
	cpuLimitCores float64
	memoryLimit   uint64
	pidsLimit     int64
	stats         *stats  // nil when not running or unreadable
	oomKills      *uint64 // nil when the cgroup's memory.events is unreadable
}

type stats struct {
	cpuSeconds          float64
	cpuThrottledSeconds float64
	memoryBytes         uint64
	tasks               uint64
	rxBytes, txBytes    uint64
	hasNetwork          bool
}

type layer struct {
	bytes      int64
	measuredAt time.Time
}

type volume struct {
	size, used, available uint64
}

type descs struct {
	running, cpuSeconds, cpuThrottled, cpuLimit, memory, memoryLimit, oomKills,
	tasks, tasksLimit, rx, tx, layerBytes, layerMeasured,
	volumeSize, volumeUsed, volumeAvailable, refreshed *prometheus.Desc
}

func New(cfg Config) *Collector {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.LayerScanInterval <= 0 {
		cfg.LayerScanInterval = 5 * time.Minute
	}
	if cfg.DockerRoot == "" {
		cfg.DockerRoot = "/var/lib/docker"
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.CgroupRoot == "" {
		cfg.CgroupRoot = "/sys/fs/cgroup"
	}
	if cfg.VolumeUsage == nil {
		cfg.VolumeUsage = statfsUsage
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	sb := []string{"sandbox_id"}
	return &Collector{
		cfg:       cfg,
		log:       cfg.Logger,
		scanNow:   make(chan struct{}, 1),
		sandboxes: map[string]*reading{},
		layers:    map[string]layer{},
		desc: descs{
			running:         prometheus.NewDesc("daytona_sandbox_running", "1 if the sandbox's container is running, 0 if it exists but is not.", sb, nil),
			cpuSeconds:      prometheus.NewDesc("daytona_sandbox_cpu_seconds_total", "CPU time the sandbox has used.", sb, nil),
			cpuThrottled:    prometheus.NewDesc("daytona_sandbox_cpu_throttled_seconds_total", "Time the sandbox spent throttled at its CPU quota.", sb, nil),
			cpuLimit:        prometheus.NewDesc("daytona_sandbox_cpu_limit_cores", "The sandbox's CPU quota in cores.", sb, nil),
			memory:          prometheus.NewDesc("daytona_sandbox_memory_bytes", "Memory the sandbox uses, excluding page cache the kernel can drop (as docker stats reports it).", sb, nil),
			memoryLimit:     prometheus.NewDesc("daytona_sandbox_memory_limit_bytes", "The sandbox's memory cap.", sb, nil),
			oomKills:        prometheus.NewDesc("daytona_sandbox_oom_kills_total", "Processes the kernel killed in the sandbox for reaching its memory cap.", sb, nil),
			tasks:           prometheus.NewDesc("daytona_sandbox_tasks", "Processes and threads running in the sandbox.", sb, nil),
			tasksLimit:      prometheus.NewDesc("daytona_sandbox_tasks_limit", "The sandbox's limit on processes and threads.", sb, nil),
			rx:              prometheus.NewDesc("daytona_sandbox_network_receive_bytes_total", "Bytes the sandbox received.", sb, nil),
			tx:              prometheus.NewDesc("daytona_sandbox_network_transmit_bytes_total", "Bytes the sandbox sent.", sb, nil),
			layerBytes:      prometheus.NewDesc("daytona_sandbox_writable_layer_bytes", "Bytes the sandbox has written to its own filesystem layer.", sb, nil),
			layerMeasured:   prometheus.NewDesc("daytona_sandbox_writable_layer_measured_timestamp_seconds", "When daytona_sandbox_writable_layer_bytes was measured.", sb, nil),
			volumeSize:      prometheus.NewDesc("daytona_runner_docker_volume_size_bytes", "Size of the filesystem holding the sandboxes' layers.", nil, nil),
			volumeUsed:      prometheus.NewDesc("daytona_runner_docker_volume_used_bytes", "Used bytes of the filesystem holding the sandboxes' layers.", nil, nil),
			volumeAvailable: prometheus.NewDesc("daytona_runner_docker_volume_available_bytes", "Bytes available to unprivileged writers on that filesystem.", nil, nil),
			refreshed:       prometheus.NewDesc("daytona_sandbox_usage_refreshed_timestamp_seconds", "When the per-sandbox readings other than the writable layer were last refreshed.", nil, nil),
		},
	}
}

// Start refreshes the readings until ctx is done.
func (c *Collector) Start(ctx context.Context) {
	go c.runRefresh(ctx)
	go c.runLayerScans(ctx)
}

func (c *Collector) runRefresh(ctx context.Context) {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		c.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (c *Collector) runLayerScans(ctx context.Context) {
	t := time.NewTicker(c.cfg.LayerScanInterval)
	defer t.Stop()
	c.scanLayers(ctx)
	last := c.cfg.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.scanNow:
			if c.cfg.Now().Sub(last) < minLayerScanGap {
				continue // the next refresh asks again if growth continues
			}
		}
		c.scanLayers(ctx)
		last = c.cfg.Now()
	}
}

// refresh reads every container's CPU, memory, tasks, OOM kills and network,
// and the Docker volume, and asks for an early layer scan if the volume has
// grown fast.
func (c *Collector) refresh(ctx context.Context) {
	list, err := c.cfg.Docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		c.log.WarnContext(ctx, "sandbox usage: list containers", "error", err)
		return
	}
	next := make(map[string]*reading, len(list))
	for _, s := range list {
		id := sandboxID(s)
		if id == "" {
			continue
		}
		r := &reading{containerID: s.ID, running: s.State == container.StateRunning}
		if r.running {
			c.readRunning(ctx, r)
		}
		next[id] = r
	}
	vol := c.readVolume(ctx)

	c.mu.Lock()
	c.sandboxes = next
	if vol != nil {
		c.volume = vol
	}
	c.refreshedAt = c.cfg.Now()
	trigger := vol != nil && c.scanned && c.cfg.LayerScanTriggerBytes > 0 &&
		vol.used >= c.usedAtLastScan+c.cfg.LayerScanTriggerBytes
	c.mu.Unlock()

	if trigger {
		select {
		case c.scanNow <- struct{}{}:
		default:
		}
	}
}

func (c *Collector) readRunning(ctx context.Context, r *reading) {
	ictx, cancel := context.WithTimeout(ctx, perContainerTimeout)
	info, _, err := c.cfg.Docker.ContainerInspectWithRaw(ictx, r.containerID, false)
	cancel()
	if err == nil && info.ContainerJSONBase != nil {
		if hc := info.HostConfig; hc != nil {
			switch {
			case hc.CPUQuota > 0 && hc.CPUPeriod > 0:
				r.cpuLimitCores = float64(hc.CPUQuota) / float64(hc.CPUPeriod)
			case hc.NanoCPUs > 0:
				r.cpuLimitCores = float64(hc.NanoCPUs) / 1e9
			}
			if hc.Memory > 0 {
				r.memoryLimit = uint64(hc.Memory)
			}
			if hc.PidsLimit != nil && *hc.PidsLimit > 0 {
				r.pidsLimit = *hc.PidsLimit
			}
		}
		if info.State != nil && info.State.Pid > 0 {
			if n, ok := c.readOOMKills(info.State.Pid); ok {
				r.oomKills = &n
			}
		}
	} else if err != nil {
		c.log.DebugContext(ctx, "sandbox usage: inspect", "container", r.containerID, "error", err)
	}

	sctx, cancel := context.WithTimeout(ctx, perContainerTimeout)
	defer cancel()
	resp, err := c.cfg.Docker.ContainerStatsOneShot(sctx, r.containerID)
	if err != nil {
		c.log.DebugContext(ctx, "sandbox usage: stats", "container", r.containerID, "error", err)
		return
	}
	defer resp.Body.Close()
	var st container.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		c.log.DebugContext(ctx, "sandbox usage: decode stats", "container", r.containerID, "error", err)
		return
	}
	r.stats = statsFrom(st)
}

// statsFrom keeps the numbers the collector exports from a Docker stats
// response.
func statsFrom(st container.StatsResponse) *stats {
	s := &stats{
		cpuSeconds:          float64(st.CPUStats.CPUUsage.TotalUsage) / 1e9,
		cpuThrottledSeconds: float64(st.CPUStats.ThrottlingData.ThrottledTime) / 1e9,
		memoryBytes:         st.MemoryStats.Usage,
		tasks:               st.PidsStats.Current,
	}
	// As docker stats does: page cache the kernel can drop doesn't count.
	for _, k := range []string{"inactive_file", "total_inactive_file"} {
		if v, ok := st.MemoryStats.Stats[k]; ok {
			if v < s.memoryBytes {
				s.memoryBytes -= v
			}
			break
		}
	}
	for _, n := range st.Networks {
		s.rxBytes += n.RxBytes
		s.txBytes += n.TxBytes
		s.hasNetwork = true
	}
	return s
}

// readOOMKills reads oom_kill from the memory.events of pid's cgroup (v2).
// Docker's stats don't carry it, and a process killed inside a sandbox that
// keeps running shows up nowhere else.
func (c *Collector) readOOMKills(pid int) (uint64, bool) {
	data, err := os.ReadFile(filepath.Join(c.cfg.ProcRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return 0, false
	}
	path, ok := cgroupV2Path(string(data))
	if !ok {
		return 0, false
	}
	events, err := os.ReadFile(filepath.Join(c.cfg.CgroupRoot, path, "memory.events"))
	if err != nil {
		return 0, false
	}
	return keyedValue(string(events), "oom_kill")
}

// cgroupV2Path returns the unified-hierarchy path in a /proc/<pid>/cgroup
// file. The path is relative to the reader's cgroup namespace; one that
// leaves it ("/.." prefixes) is refused.
func cgroupV2Path(procCgroup string) (string, bool) {
	for _, line := range strings.Split(procCgroup, "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			p = strings.TrimSpace(p)
			if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
				return "", false
			}
			return p, true
		}
	}
	return "", false
}

// keyedValue returns the value of key in a flat-keyed cgroup file
// ("key value" per line).
func keyedValue(content, key string) (uint64, bool) {
	for _, line := range strings.Split(content, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			v, err := strconv.ParseUint(f[1], 10, 64)
			return v, err == nil
		}
	}
	return 0, false
}

func (c *Collector) readVolume(ctx context.Context) *volume {
	size, used, avail, err := c.cfg.VolumeUsage(ctx, c.cfg.DockerRoot)
	if err != nil {
		c.log.WarnContext(ctx, "sandbox usage: docker volume", "error", err)
		return nil
	}
	return &volume{size: size, used: used, available: avail}
}

// scanLayers sizes every container's writable layer, one at a time.
func (c *Collector) scanLayers(ctx context.Context) {
	if vol := c.readVolume(ctx); vol != nil {
		c.mu.Lock()
		c.usedAtLastScan = vol.used
		c.scanned = true
		c.mu.Unlock()
	}
	list, err := c.cfg.Docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		c.log.WarnContext(ctx, "sandbox usage: list containers for layer scan", "error", err)
		return
	}
	measured := make(map[string]layer, len(list))
	for _, s := range list {
		id := sandboxID(s)
		if id == "" {
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, layerSizeTimeout)
		info, _, err := c.cfg.Docker.ContainerInspectWithRaw(lctx, s.ID, true)
		cancel()
		if err != nil || info.SizeRw == nil {
			c.log.DebugContext(ctx, "sandbox usage: size layer", "container", s.ID, "error", err)
			continue
		}
		measured[id] = layer{bytes: *info.SizeRw, measuredAt: c.cfg.Now()}
		if ctx.Err() != nil {
			return
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]layer, len(list))
	for _, s := range list {
		id := sandboxID(s)
		if l, ok := measured[id]; ok {
			next[id] = l
		} else if old, ok := c.layers[id]; ok {
			next[id] = old // keep the last size; its timestamp shows its age
		}
	}
	c.layers = next
}

// sandboxID is the container's name, which the runner sets to the sandbox ID.
func sandboxID(s container.Summary) string {
	if len(s.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

func statfsUsage(ctx context.Context, path string) (uint64, uint64, uint64, error) {
	u, err := disk.UsageWithContext(ctx, path)
	if err != nil {
		return 0, 0, 0, err
	}
	return u.Total, u.Used, u.Free, nil
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	d := c.desc
	for _, x := range []*prometheus.Desc{d.running, d.cpuSeconds, d.cpuThrottled, d.cpuLimit, d.memory, d.memoryLimit,
		d.oomKills, d.tasks, d.tasksLimit, d.rx, d.tx, d.layerBytes, d.layerMeasured,
		d.volumeSize, d.volumeUsed, d.volumeAvailable, d.refreshed} {
		ch <- x
	}
}

// Collect implements prometheus.Collector from the latest readings. A sandbox
// gone from the latest container list is gone from the output.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.desc
	gauge := func(desc *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v, labels...)
	}
	counter := func(desc *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, v, labels...)
	}
	for id, r := range c.sandboxes {
		running := 0.0
		if r.running {
			running = 1
		}
		gauge(d.running, running, id)
		if r.cpuLimitCores > 0 {
			gauge(d.cpuLimit, r.cpuLimitCores, id)
		}
		if r.memoryLimit > 0 {
			gauge(d.memoryLimit, float64(r.memoryLimit), id)
		}
		if r.pidsLimit > 0 {
			gauge(d.tasksLimit, float64(r.pidsLimit), id)
		}
		if s := r.stats; s != nil {
			counter(d.cpuSeconds, s.cpuSeconds, id)
			counter(d.cpuThrottled, s.cpuThrottledSeconds, id)
			gauge(d.memory, float64(s.memoryBytes), id)
			gauge(d.tasks, float64(s.tasks), id)
			if s.hasNetwork {
				counter(d.rx, float64(s.rxBytes), id)
				counter(d.tx, float64(s.txBytes), id)
			}
		}
		if r.oomKills != nil {
			counter(d.oomKills, float64(*r.oomKills), id)
		}
		if l, ok := c.layers[id]; ok {
			gauge(d.layerBytes, float64(l.bytes), id)
			gauge(d.layerMeasured, float64(l.measuredAt.Unix()), id)
		}
	}
	if v := c.volume; v != nil {
		gauge(d.volumeSize, float64(v.size))
		gauge(d.volumeUsed, float64(v.used))
		gauge(d.volumeAvailable, float64(v.available))
	}
	if !c.refreshedAt.IsZero() {
		gauge(d.refreshed, float64(c.refreshedAt.Unix()))
	}
}

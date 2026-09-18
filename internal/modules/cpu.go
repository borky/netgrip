// cpu.go — what the CPU is actually doing, per core.
//
// A single "CPU 40%" number is misleading on a router. Receive processing
// is pinned to whichever core handles the NIC interrupt, so a box can be
// routing at its ceiling with one core saturated and three idle, and the
// average will look comfortable. This probe reports each core separately,
// and alongside them the two counters that say whether the network path is
// keeping up: packets dropped because the backlog was full, and softirq
// budget exhaustions ("squeezes").
//
// Everything is read from /proc and /sys. No subprocesses: this is polled
// from a dashboard, and shelling out per poll is how a listing once cost
// six seconds (see ListClients).
package modules

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUCore is one core: how busy it is, how fast it is clocked, and whether
// it is losing packets.
type CPUCore struct {
	Idx      int     `json:"idx"`
	UsagePct float64 `json:"usage_pct"`
	FreqMHz  int     `json:"freq_mhz,omitempty"`
	// Dropped/Squeezed are since boot; the Rate fields are per second since
	// the previous poll, which is the number that tells you it is happening
	// now rather than having happened once months ago.
	Dropped      int64   `json:"dropped"`
	DroppedRate  float64 `json:"dropped_rate"`
	Squeezed     int64   `json:"squeezed"`
	SqueezedRate float64 `json:"squeezed_rate"`
}

// CPUProc is a process worth naming in a "what is using the CPU" list.
type CPUProc struct {
	PID      int     `json:"pid"`
	Name     string  `json:"name"`
	UsagePct float64 `json:"usage_pct"`
}

// CPUProbe is the whole picture for one poll.
type CPUProbe struct {
	// Cores in order. Empty on the very first poll: usage is a delta, and
	// there is nothing to compare against yet.
	Cores []CPUCore `json:"cores"`
	// UsagePct across all cores, kept because it is what people expect to
	// see first — but the per-core list is the honest one.
	UsagePct float64 `json:"usage_pct"`
	// Busiest is the highest single core. On a router this is the number
	// that predicts trouble, not the average.
	Busiest  float64   `json:"busiest_pct"`
	Load     []float64 `json:"load"`
	Governor string    `json:"governor,omitempty"`
	// TempC with the chip it came from: a board may expose no CPU sensor at
	// all, and a WiFi radio idles warmer than a SoC. Saying which avoids
	// reading a healthy router as overheating.
	TempC      *float64 `json:"temp_c,omitempty"`
	TempSource string   `json:"temp_source,omitempty"`
	// Procs: the heaviest processes since the previous poll.
	Procs []CPUProc `json:"procs"`
	// Warming is true until there are two samples to compare.
	Warming bool `json:"warming"`
}

type cpuTimes struct{ total, idle float64 }

type softnetRow struct{ dropped, squeezed int64 }

var cpuState struct {
	mu       sync.Mutex
	at       time.Time
	cores    []cpuTimes
	softnet  []softnetRow
	procs    map[int]float64
	procName map[int]string
}

// readCPUTimes parses the per-core lines of /proc/stat.
func readCPUTimes() []cpuTimes {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	return parseCPUTimes(string(b))
}

// parseCPUTimes reads the per-core lines, skipping the "cpu " aggregate.
func parseCPUTimes(doc string) []cpuTimes {
	var out []cpuTimes
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		var t cpuTimes
		for i := 1; i < len(f); i++ {
			v, err := strconv.ParseFloat(f[i], 64)
			if err != nil {
				continue
			}
			t.total += v
			// Fields 4 and 5 are idle and iowait: both are "not working".
			if i == 4 || i == 5 {
				t.idle += v
			}
		}
		out = append(out, t)
	}
	return out
}

// readSoftnet parses /proc/net/softnet_stat: one hex row per core, of which
// column 2 is packets dropped and column 3 the times the softirq handler
// ran out of budget with work left.
func readSoftnet() []softnetRow {
	b, err := os.ReadFile("/proc/net/softnet_stat")
	if err != nil {
		return nil
	}
	return parseSoftnet(string(b))
}

// parseSoftnet decodes the hex columns of /proc/net/softnet_stat.
func parseSoftnet(doc string) []softnetRow {
	var out []softnetRow
	for _, line := range strings.Split(strings.TrimSpace(doc), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		dropped, _ := strconv.ParseInt(f[1], 16, 64)
		squeezed, _ := strconv.ParseInt(f[2], 16, 64)
		out = append(out, softnetRow{dropped: dropped, squeezed: squeezed})
	}
	return out
}

func readIntFile(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v, err == nil
}

// cpuTemp looks for a temperature, preferring a real thermal zone and
// falling back to any hwmon that offers one. Returns the reading and the
// name of whatever produced it.
func cpuTemp() (*float64, string) {
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*")
	for _, z := range zones {
		if v, ok := readIntFile(z + "/temp"); ok && v > 0 {
			c := float64(v) / 1000
			name := strings.TrimSpace(readString(z + "/type"))
			if name == "" {
				name = "thermal_zone"
			}
			return &c, name
		}
	}
	mons, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, m := range mons {
		if v, ok := readIntFile(m + "/temp1_input"); ok && v > 0 {
			c := float64(v) / 1000
			name := strings.TrimSpace(readString(m + "/name"))
			if name == "" {
				name = "hwmon"
			}
			return &c, name
		}
	}
	return nil, ""
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readProcTicks returns CPU ticks per process and their names, from
// /proc/<pid>/stat. Reading a couple of hundred small files costs about a
// millisecond; spawning anything would cost far more.
func readProcTicks() (map[int]float64, map[int]string) {
	ticks := map[int]float64{}
	names := map[int]string{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ticks, names
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		s := string(b)
		// The command is in parentheses and may contain spaces, so split
		// after the closing one.
		open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || close < open {
			continue
		}
		name := s[open+1 : close]
		f := strings.Fields(s[close+1:])
		// utime and stime are fields 14 and 15 of the whole line, which are
		// 12 and 13 of what follows the command.
		if len(f) < 13 {
			continue
		}
		utime, _ := strconv.ParseFloat(f[11], 64)
		stime, _ := strconv.ParseFloat(f[12], 64)
		ticks[pid] = utime + stime
		names[pid] = name
	}
	return ticks, names
}

// clockTicks is USER_HZ. Linux fixes it at 100 on every architecture
// Go builds for here; reading it properly needs cgo.
const clockTicks = 100.0

// ProbeCPU samples the CPU and compares against the previous poll.
//
// The first call after start has nothing to compare against and reports
// Warming, with no percentages: a value computed from boot-time totals
// would describe the average since boot, not what is happening now.
func ProbeCPU() *CPUProbe {
	p := &CPUProbe{Cores: []CPUCore{}, Procs: []CPUProc{}, Load: []float64{}}

	if f := strings.Fields(readString("/proc/loadavg")); len(f) >= 3 {
		for _, v := range f[:3] {
			if n, err := strconv.ParseFloat(v, 64); err == nil {
				p.Load = append(p.Load, n)
			}
		}
	}
	p.Governor = readString("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
	p.TempC, p.TempSource = cpuTemp()

	now := time.Now()
	cores := readCPUTimes()
	softnet := readSoftnet()
	ticks, names := readProcTicks()

	cpuState.mu.Lock()
	prevAt, prevCores, prevSoftnet, prevProcs := cpuState.at, cpuState.cores, cpuState.softnet, cpuState.procs
	cpuState.at, cpuState.cores, cpuState.softnet, cpuState.procs, cpuState.procName = now, cores, softnet, ticks, names
	cpuState.mu.Unlock()

	elapsed := now.Sub(prevAt).Seconds()
	if prevAt.IsZero() || elapsed <= 0 || len(prevCores) != len(cores) {
		p.Warming = true
		return p
	}

	var busiest, sum float64
	for i, c := range cores {
		dTotal := c.total - prevCores[i].total
		dIdle := c.idle - prevCores[i].idle
		usage := 0.0
		if dTotal > 0 {
			usage = (dTotal - dIdle) / dTotal * 100
		}
		core := CPUCore{Idx: i, UsagePct: round1(usage)}
		if mhz, ok := readIntFile("/sys/devices/system/cpu/cpu" + strconv.Itoa(i) + "/cpufreq/scaling_cur_freq"); ok {
			core.FreqMHz = mhz / 1000
		}
		if i < len(softnet) {
			core.Dropped = softnet[i].dropped
			core.Squeezed = softnet[i].squeezed
			if i < len(prevSoftnet) {
				core.DroppedRate = round1(float64(softnet[i].dropped-prevSoftnet[i].dropped) / elapsed)
				core.SqueezedRate = round1(float64(softnet[i].squeezed-prevSoftnet[i].squeezed) / elapsed)
			}
		}
		p.Cores = append(p.Cores, core)
		sum += usage
		if usage > busiest {
			busiest = usage
		}
	}
	if len(cores) > 0 {
		p.UsagePct = round1(sum / float64(len(cores)))
	}
	p.Busiest = round1(busiest)

	for pid, t := range ticks {
		prev, ok := prevProcs[pid]
		if !ok || t <= prev {
			continue
		}
		pct := (t - prev) / clockTicks / elapsed * 100
		if pct < 0.5 {
			continue
		}
		p.Procs = append(p.Procs, CPUProc{PID: pid, Name: names[pid], UsagePct: round1(pct)})
	}
	sort.Slice(p.Procs, func(i, j int) bool { return p.Procs[i].UsagePct > p.Procs[j].UsagePct })
	if len(p.Procs) > 5 {
		p.Procs = p.Procs[:5]
	}
	return p
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

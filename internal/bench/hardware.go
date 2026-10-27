package bench

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// maxProcFile bounds every read of a /proc file.
const maxProcFile = 4 << 20

// Hardware describes the machine and the directory a benchmark ran on.
// It goes into the benchmark output only.
type Hardware struct {
	GOOS, GOARCH string
	GoVersion    string
	NumCPU       int
	GOMAXPROCS   int
	CPUModel     string // /proc/cpuinfo "model name"
	Kernel       string // /proc/version up to the build details
	MemTotal     string // /proc/meminfo "MemTotal"
	Dir          string // the directory the benchmark data lives in
	FS           string // file system type of Dir from /proc/mounts
	Mount        string // mount point of Dir
	Device       string // device of that mount
}

// readProc reads a /proc file of at most maxProcFile bytes.
func readProc(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcFile {
		return nil, errors.New("bench: proc file too large")
	}
	return data, nil
}

// procField returns the value of the first "key: value" line of a /proc
// file whose key is key (spaces and tabs around the colon ignored).
func procField(data []byte, key string) string {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// unescapeMount decodes the octal escapes of /proc/mounts (\040 for a
// space and so on).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountOf returns device, mount point and file system type of the mount
// in /proc/mounts that holds path (the longest matching mount point).
func mountOf(mounts []byte, path string) (dev, mnt, fs string) {
	sc := bufio.NewScanner(bytes.NewReader(mounts))
	best := -1
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		mp := unescapeMount(f[1])
		inside := path == mp || mp == "/" || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/")
		// Later lines of the same mount point shadow earlier ones.
		if inside && len(mp) >= best {
			best, dev, mnt, fs = len(mp), unescapeMount(f[0]), mp, f[2]
		}
	}
	return dev, mnt, fs
}

// CollectHardware describes this machine and the file system of dir.
// Values that cannot be read are "unknown".
func CollectHardware(dir string) Hardware {
	h := Hardware{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(),
		NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		CPUModel: "unknown", Kernel: "unknown", MemTotal: "unknown", FS: "unknown", Mount: "unknown", Device: "unknown",
	}
	if data, err := readProc("/proc/cpuinfo"); err == nil {
		for _, key := range []string{"model name", "Model", "Hardware", "cpu model", "Processor"} {
			if v := procField(data, key); v != "" {
				h.CPUModel = v
				break
			}
		}
	}
	if data, err := readProc("/proc/version"); err == nil {
		v := strings.TrimSpace(string(data))
		if i := strings.Index(v, " ("); i > 0 {
			v = v[:i]
		}
		if v != "" {
			h.Kernel = v
		}
	}
	if data, err := readProc("/proc/meminfo"); err == nil {
		if v := procField(data, "MemTotal"); v != "" {
			h.MemTotal = v
		}
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		h.Dir = abs
		if data, err := readProc("/proc/mounts"); err == nil {
			if dev, mnt, fs := mountOf(data, abs); fs != "" {
				h.Device, h.Mount, h.FS = dev, mnt, fs
			}
		}
	}
	return h
}

// Lines returns the description as "key: value" lines, the configuration
// format of Go benchmark output that benchstat understands.
func (h Hardware) Lines() []string {
	return []string{
		"goversion: " + h.GoVersion,
		"numcpu: " + strconv.Itoa(h.NumCPU),
		"gomaxprocs: " + strconv.Itoa(h.GOMAXPROCS),
		"cpumodel: " + h.CPUModel,
		"memtotal: " + h.MemTotal,
		"kernel: " + h.Kernel,
		"benchdir: " + h.Dir,
		"benchfs: " + h.FS + " on " + h.Mount + " (" + h.Device + ")",
	}
}

// ReadVmRSS returns the resident set size of this process in bytes from
// /proc/self/status, or 0 where it cannot be read.
func ReadVmRSS() uint64 {
	data, err := readProc("/proc/self/status")
	if err != nil {
		return 0
	}
	v := strings.TrimSuffix(procField(data, "VmRSS"), " kB")
	kb, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0
	}
	return kb << 10
}

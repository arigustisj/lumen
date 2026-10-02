// Command lumen memetakan permukaan aplikasi web untuk pengujian keamanan.
//
// Directory: ~/projects/tools/lumen
//
// Alat ini dirancang untuk SPA (React/Next/Vue) di mana rute API tidak ada
// di HTML. HTML dari aplikasi semacam itu hanya berisi satu div kosong dan
// beberapa tag <script>; crawler biasa akan selalu melaporkan "halaman login
// saja". Rute sebenarnya ada sebagai string literal di dalam JavaScript
// bundle, dan bagian paling berguna dari alat ini adalah membacanya.
//
// Prinsip yang dipegang:
//
//   - Satu origin. Guard di internal/scope memblokir host lain dan mencatat
//     penolakannya, jadi invariansi "hanya menyentuh target" bisa diaudit.
//   - Tidak ada metode destruktif. Hanya GET dan OPTIONS.
//   - Tidak menyimpulkan kerentanan. Alat ini menunjuk hal yang menarik;
//     penilaian tetap milik manusia.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/arigustisj/lumen"
)

// Nilai bawaan flag, dipakai untuk membedakan "user tidak menetapkannya"
// dari "user menetapkannya dengan nilai yang sama". Config hanya menimpa
// yang tidak ditegaskan user secara eksplisit.
const (
	defaultDelay   = 250 * time.Millisecond
	defaultConc    = 4
	defaultTimeout = 3 * time.Minute
)

func main() {
	var (
		target      = flag.String("target", "", "URL target (lewati beranda dan langsung pindai)")
		name        = flag.String("name", "", "nama target di laporan")
		outDir      = flag.String("out", "out", "folder output")
		conc        = flag.Int("conc", defaultConc, "request paralel")
		delay       = flag.Duration("delay", defaultDelay, "jeda minimal antar request")
		timeout     = flag.Duration("timeout", defaultTimeout, "batas waktu per scan")
		noProbe     = flag.Bool("probe", true, "verifikasi endpoint hasil ekstraksi JS dengan OPTIONS")
		sarif       = flag.Bool("sarif", true, "tulis SARIF 2.1.0 untuk GitHub code scanning")
		markdown    = flag.Bool("markdown", true, "tulis laporan .md untuk agent AI")
		quiet       = flag.Bool("quiet", false, "tanpa ringkasan di layar")
		versionFlag = flag.Bool("version", false, "tampilkan versi lalu keluar")
		noCol       = flag.Bool("no-color", false, "matikan warna (default: autodeteksi terminal)")
		asciiOnly   = flag.Bool("ascii", false, "karakter ASCII, bukan unicode")
		width       = flag.Int("width", 0, "lebar kolom; 0 = autodeteksi. Berguna di Termux")
		compact     = flag.Bool("compact", false, "ringkas: batas daftar per kategori")
		exitZero    = flag.Bool("exit-zero", false, "selalu keluar dengan kode 0 (untuk pemakaian manual)")
		noTUI       = flag.Bool("no-tui", false, "paksa output teks biasa, tanpa dashboard")
		noDNSFix    = flag.Bool("no-dns-fallback", false, "jangan mencoba resolver publik saat DNS perangkat memblokir")

		cfgPath  = flag.String("config", "", "file konfigurasi YAML (multi-target, token authz)")
		_        = noCol
		_        = asciiOnly
		_        = width
		runAuthz = flag.Bool("authz", false, "pemeriksaan otorisasi diferensial (butuh config + token)")
	)
	flag.Usage = usage
	flag.Parse()

	if *versionFlag {
		fmt.Printf("%s %s · %s · by %s\n", lumen.Name, lumen.Version, lumen.Tagline, lumen.Author)
		return
	}

	opts := plainOpts{
		outDir: *outDir, conc: *conc, delay: *delay, timeout: *timeout,
		doProbe: *noProbe, writeSARIF: *sarif, noDNSFix: *noDNSFix,
		compact: *compact, quiet: *quiet,
	}
	_ = markdown // markdown selalu ditulis bersama JSON; flag kept for symmetry

	cfg, err := loadConfigInto(&opts, *cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}

	jobs, extraAuthz := resolveJobs(cfg, target, name, runAuthz)
	if len(jobs) == 0 && !interactive(*noTUI) {
		flag.Usage()
		os.Exit(2)
	}

	// Dashboard interaktif.(&: Beranda → riwayat → laporan.)
	if interactive(*noTUI) && (len(jobs) == 0 || len(jobs) == 1 && *target != "") {
		sh, err := newShell(opts)
		if err != nil {
			fatal("%v", err)
		}
		if len(jobs) == 1 {
			// Target disebut di baris perintah: langsung pindai tanpa
			// perlu mengetik ulang.
			j := jobs[0]
			j.authz = j.authz || extraAuthz
			sh.pending = &j
		}
		if _, err := tea.NewProgram(sh, tea.WithAltScreen()).Run(); err != nil {
			fmt.Fprintln(os.Stderr, "dashboard tidak bisa dibuka:", err)
			return
		}
		return
	}

	// Jalur non-interaktif: semua target dipindai berurutan.
	worst := 0
	for _, j := range jobs {
		j.authz = j.authz || extraAuthz
		runPlain(j, opts)
		if r, err := lastExitCode(&opts, j); err == nil && r > worst {
			worst = r
		}
	}
	if *exitZero {
		return
	}
	os.Exit(worst)
}

// interactive menandai apakah dashboard boleh dipakai.
func interactive(noTUI bool) bool { return !noTUI && isTerminal(os.Stdout) }

// lastExitCode menghitung kode keluar dari run terakhir sebuah target.
func lastExitCode(opts *plainOpts, j job) (int, error) {
	store, err := lumen.OpenStore(opts.outDir)
	if err != nil {
		return 0, err
	}
	var latest *lumen.Run
	for _, r := range store.Runs() {
		if r.Target == j.url || strings.Contains(r.Target, j.name) {
			rr := r
			latest = &rr
		}
	}
	if latest == nil {
		return 0, nil
	}
	rep, err := store.LoadRun(*latest)
	if err != nil {
		return 0, err
	}
	return lumen.ExitCode(*rep, rep.Candidates), nil
}

// loadConfigInto menerapkan nilai bawaan dari file konfigurasi ke opts.
func loadConfigInto(opts *plainOpts, path string) (lumen.Config, error) {
	var cfg lumen.Config
	if path == "" {
		return cfg, nil
	}
	cfg, err := lumen.LoadConfig(path)
	if err != nil {
		return cfg, err
	}
	if cfg.Defaults.Delay != "" && opts.delay == defaultDelay {
		if opts.delay, err = time.ParseDuration(cfg.Defaults.Delay); err != nil {
			return cfg, fmt.Errorf("config defaults.delay: %w", err)
		}
	}
	if cfg.Defaults.Conc > 0 && opts.conc == defaultConc {
		opts.conc = cfg.Defaults.Conc
	}
	if cfg.Defaults.Timeout != "" && opts.timeout == defaultTimeout {
		if opts.timeout, err = time.ParseDuration(cfg.Defaults.Timeout); err != nil {
			return cfg, fmt.Errorf("config defaults.timeout: %w", err)
		}
	}
	opts.doProbe = cfg.Defaults.Probe || opts.doProbe
	return cfg, nil
}

// resolveJobs menyusun daftar target dari config dan flag.
func resolveJobs(cfg lumen.Config, target, name *string, authz *bool) ([]job, bool) {
	var out []job
	extra := *authz
	for _, t := range cfg.Targets {
		if t.Authz && !extra {
			continue
		}
		out = append(out, job{name: t.Name, url: t.URL, authz: t.Authz, toks: t.Tokens})
	}
	if *target != "" {
		j := job{url: *target, name: *name}
		if j.name == "" {
			j.name = hostOf(*target)
		}
		out = append(out, j)
	}
	return out, extra
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

// job adalah satu target yang akan dipindai. Didefinisikan di level
// package supaya bisa dipakai oleh runner TUI.
type job struct {
	name  string
	url   string
	authz bool
	toks  lumen.Tokens
}

// applyProbe menjalankan verifikasi OPTIONS lalu menggabungkan hasilnya ke
// endpoint asal. Status dan flag ditulis balik ke slice yang sama supaya
// tidak ada dua sumber kebenaran.
func applyProbe(ctx context.Context, m *lumen.Mapper, eps *[]lumen.Endpoint, findings *[]lumen.Finding, conc int) {
	list := *eps
	probed := lumen.ProbeEndpoints(ctx, m, list, lumen.ProbeOptions{Conc: conc})

	byKey := map[string]lumen.Endpoint{}
	for _, e := range list {
		byKey[e.Method+" "+e.Path] = e
	}
	for _, e := range probed {
		k := e.Method + " " + e.Path
		if orig, ok := byKey[k]; ok {
			orig.Status = e.Status
			orig.Flags = dedupStrings(append(orig.Flags, e.Flags...))
			byKey[k] = orig
		}
	}
	merged := make([]lumen.Endpoint, 0, len(byKey))
	for _, e := range byKey {
		merged = append(merged, e)
	}
	*eps = merged

	for _, e := range probed {
		if len(e.Flags) == 0 {
			continue
		}
		*findings = append(*findings, lumen.Finding{
			Kind:     "endpoint",
			Severity: lumen.FlagSeverity(e.Flags),
			Where:    e.Path,
			Detail:   fmt.Sprintf("%s -> %d %v", e.Method, e.Status, e.Flags),
		})
	}
}

var (
	cancelled bool
	stop      context.CancelFunc
)

func init() {
	// Satu context global yang bisa dibatalkan Ctrl-C, dipakai supaya
	// goroutine penangkap sinyal bisa menghentikan scan yang sedang jalan.
	var c context.Context
	c, stop = context.WithCancel(context.Background())
	_ = c
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "target"
	}
	return sanitise(u.Hostname())
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s

Pemeta permukaan aplikasi web untuk review keamanan, dengan fokus pada SPA
di mana rute API tidak ada di HTML.

Pakai:
  lumen -target https://app.example.com
  lumen -target https://app.example.com -probe=false -delay 500ms
  lumen -target https://app.example.com -delay 1s -conc 2   # lebih konservatif
  lumen -version

Hanya GET dan OPTIONS yang dikirim — tidak ada metode yang mengubah state.
Guard scope memblokir host di luar target dan mencatat penolakannya di laporan,
jadi invariansi "hanya menyentuh satu host" bisa diaudit dari output.

Alat ini tidak menyimpulkan kerentanan. Dia menunjuk hal yang menarik —
endpoint yang tidak ada di HTML, header yang hilang, kredensial yang ikut
ter-commit ke bundle. Penilaian tetap milik manusia.

Opsi tampilan:
  -no-color            matikan warna (default: autodeteksi terminal)
  -ascii               karakter ASCII, bukan unicode
  -width N             lebar kolom; 0 = autodeteksi. Berguna di Termux.

`, lumen.Banner())
	flag.PrintDefaults()
}

// dedupStrings membuang duplikasi sambil menjaga urutan.
func dedupStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func sanitise(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

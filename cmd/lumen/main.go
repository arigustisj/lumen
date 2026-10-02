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
	lumen "github.com/arigustisj/lumen"

	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
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
	log.SetFlags(0)

	var (
		target      = flag.String("target", "", "URL target, contoh https://staging.example.com")
		outDir      = flag.String("out", "out", "direktori output")
		stem        = flag.String("name", "", "nama file output tanpa ekstensi (default: dari host target)")
		conc        = flag.Int("conc", defaultConc, "request paralel")
		delay       = flag.Duration("delay", defaultDelay, "jeda minimal antar request")
		doProbe     = flag.Bool("probe", true, "verifikasi endpoint hasil ekstraksi JS (OPTIONS saja)")
		timeout     = flag.Duration("timeout", defaultTimeout, "batas waktu total")
		quiet       = flag.Bool("quiet", false, "hanya cetak ringkasan singkat")
		noCol       = flag.Bool("no-color", false, "matikan warna (default: autodeteksi terminal)")
		ascii       = flag.Bool("ascii", false, "pakai karakter ASCII, bukan unicode")
		width       = flag.Int("width", 0, "lebar output kolom; 0 = autodeteksi (berguna di Termux)")
		showVer     = flag.Bool("version", false, "tampilkan versi lalu keluar")
		sarif       = flag.Bool("sarif", true, "tulis findings.sarif (SARIF 2.1.0) untuk CI/code scanning")
		exitZero    = flag.Bool("exit-zero", false, "selalu keluar dengan kode 0 (untuk pemakaian manual)")
		compact     = flag.Bool("compact", false, "ringkas: batas daftar per kategori")
		cfgPath     = flag.String("config", "", "file konfigurasi YAML (multi-target, token authz)")
		runAuthz    = flag.Bool("authz", false, "pemeriksaan otorisasi diferensial (butuh config + token)")
		tuiMode     = flag.Bool("tui", false, "dashboard interaktif")
		tuiDisabled = flag.Bool("no-tui", false, "paksa output teks biasa, tanpa dashboard")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println(lumen.Banner())
		return
	}
	// Config multi-target. Kalau ada, dia yang menentukan apa yang dipindai;
	// -target dipakai untuk menambah satu target di luar config.
	var cfg lumen.Config
	if *cfgPath != "" {
		var err error
		if cfg, err = lumen.LoadConfig(*cfgPath); err != nil {
			log.Fatalf("config: %v", err)
		}
		if cfg.Defaults.Delay != "" && *delay == defaultDelay {
			if *delay, err = time.ParseDuration(cfg.Defaults.Delay); err != nil {
				log.Fatalf("config defaults.delay: %v", err)
			}
		}
		if cfg.Defaults.Conc > 0 && *conc == defaultConc {
			*conc = cfg.Defaults.Conc
		}
		if cfg.Defaults.Timeout != "" && *timeout == defaultTimeout {
			if *timeout, err = time.ParseDuration(cfg.Defaults.Timeout); err != nil {
				log.Fatalf("config defaults.timeout: %v", err)
			}
		}
	}

	// Target boleh datang dari env var. Di HP, mengetik URL panjang di
	// keyboard virtual itu lambat dan gampang nekan ENTER di tengah kata
	// (yang terjadi ke kita: "-wi" + "dth"). Sekali set, selamanya pakai
	// nama pendek.
	if *target == "" {
		*target = os.Getenv("LUMEN_TARGET")
	}

	// job didefinisikan di luar main supaya cmd/tui.go bisa memakainya
	// saat menjalankan pemetaan ulang.
	var jobs []job
	for _, t := range cfg.Targets {
		// Target authz hanya dipindai kalau authz diminta. Tanpa flag itu,
		// pemetaan tetap jalan seperti biasa.
		if t.Authz && !*runAuthz {
			continue
		}
		jobs = append(jobs, job{t.Name, t.URL, t.Authz, t.Tokens})
	}
	if *target != "" {
		j := job{url: *target, name: *stem}
		if j.name == "" {
			j.name = hostOf(j.url)
		}
		jobs = append(jobs, j)
	}
	if len(jobs) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *runAuthz && !cfg.HasAuthz() {
		log.Fatalf("-authz butuh -config yang punya target dengan authz: true")
	}

	// Gaya tampilan ditentukan sekali, di sini, lalu diteruskan ke report.
	// Deteksi otomatis: di Termux stdout bukan TTY saat di-pipe, jadi warna
	// mati sendiri — dan LUMEN_COLOR=always menghidupkannya lagi.
	style := lumen.DetectStyle(os.Stdout)
	if *noCol || os.Getenv("NO_COLOR") != "" {
		style.Color = false
	}
	if *ascii {
		style.Unicode = false
	}
	if *width > 0 {
		style.Width = *width
	}

	// Ctrl-C menghentikan dengan rapi dan tetap menulis laporan yang sudah
	// terkumpul. Laporan parsial jauh lebih berguna daripada tidak ada.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\ndihentikan — menulis laporan parsial")
		cancelled = true
		stop()
	}()

	worst := 0
	for _, j := range jobs {
		u, err := url.Parse(j.url)
		if err != nil || u.Host == "" {
			log.Fatalf("URL tidak valid (%s): %v", j.url, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			log.Fatalf("scheme harus http atau https, dapat %q (%s)", u.Scheme, j.url)
		}

		jobCtx, jobCancel := context.WithTimeout(context.Background(), *timeout)
		start := time.Now()

		m := lumen.NewMapper(lumen.MapperConfig{Target: u, Conc: *conc, Delay: *delay})
		m.Run(jobCtx)
		pages, eps, findings, stats := m.Snapshot()

		if *doProbe {
			applyProbe(jobCtx, m, &eps, &findings, *conc)
		}
		findings = lumen.BySeverity(findings)

		cands := lumen.Classify(eps, findings)
		cov := lumen.BuildCoverage(lumen.Report{Stats: stats})

		rep := lumen.Report{
			Target:      u.String(),
			GeneratedAt: time.Now().UTC(),
			DurationMS:  time.Since(start).Milliseconds(),
			Pages:       pages,
			Endpoints:   eps,
			Findings:    findings,
			ScopeDenied: m.Scope().Denied(),
			RootError:   m.RootError(),
			Stats:       stats,
			Candidates:  cands,
			Coverage:    cov,
		}

		// Pemeriksaan otorisasi diferensial. Hanya GET; endpoint write tidak
		// pernah dipanggil karena memanggilnya berarti menjalankan write yang
		// tidak perlu terjadi hanya untuk membuktikan sesuatu.
		var authzReps []lumen.AuthzReport
		if j.authz {
			tg := lumen.Target{Name: j.name, URL: j.url, Authz: true, Tokens: j.toks}
			names := tg.TokenNames()
			if len(names) < 2 {
				log.Fatalf("target %s: authz butuh minimal 2 perspektif", j.name)
			}
			opts := lumen.AuthzOptions{
				Baseline:  "anon",
				Compare:   names[1:],
				DelayMS:   int(delay.Milliseconds()),
				OnlyPaths: cfg.Defaults.AuthzOnly,
				SkipPaths: cfg.Defaults.AuthzSkip,
			}
			ar, err := lumen.RunAuthz(jobCtx, tg.HTTPClient(), tg, eps, opts)
			if err != nil && jobCtx.Err() == nil {
				log.Fatalf("authz %s: %v", j.name, err)
			}
			for _, r := range ar.Results {
				if f := lumen.FindingFromAuthz(r); f != nil {
					rep.Findings = append(rep.Findings, *f)
				}
			}
			rep.Findings = lumen.BySeverity(rep.Findings)
			rep.Authz = &ar
			authzReps = append(authzReps, ar)
		}

		code := lumen.ExitCode(lumen.Report{Stats: stats}, cands)
		if j.authz && code == 0 {
			code = lumen.ExitCode(rep, cands)
		}
		if code > worst {
			worst = code
		}

		name := j.name
		if name == "" {
			name = sanitise(u.Hostname())
		}
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			log.Fatalf("gagal membuat folder output: %v", err)
		}
		jsonPath := filepath.Join(*outDir, name+".json")
		textPath := filepath.Join(*outDir, name+".txt")
		compact := *compact || style.Width < 70
		if err := lumen.SaveReport(jsonPath, textPath, rep, style, cands, cov, compact, authzReps); err != nil {
			log.Fatalf("gagal menulis laporan: %v", err)
		}

		// SARIF 2.1.0: format yang sudah dipahami GitHub code scanning,
		// GitLab, dan sebagian besar pipeline.
		sarifPath := filepath.Join(*outDir, name+".sarif")
		if *sarif {
			if err := lumen.WriteSARIF(sarifPath, lumen.BuildSARIF(rep, cands, cov, code)); err != nil {
				log.Fatalf("gagal menulis SARIF: %v", err)
			}
		}

		if *quiet {
			jobCancel()
			continue
		}

		// TUI hanya masuk akal untuk satu target: kalau beberapa, pengguna
		// tidak bisa tahu sedang melihat yang mana tanpa menambah Kali ini
		// jadi pilihan, bukan kewajiban.
		useTUI := false
		if *tuiMode || !*tuiDisabled {
			useTUI = len(jobs) == 1 && isTerminal(os.Stdout)
		}
		if useTUI {
			runTUI(name, &rep, cands, cov, compact, authzReps, jsonPath, textPath, sarifPath, *sarif, *conc, *delay, *timeout, *doProbe, j)
		} else {
			fmt.Print(lumen.Render(rep, style, cands, cov, compact, authzReps))
			fmt.Print(lumen.Footer(jsonPath, textPath, style, sarifPath, *sarif))
		}
		jobCancel()

		if cancelled {
			break
		}
	}

	// Exit code hanya berarti kalau aman dipakai di pipeline; kalau human
	// yang menjalankan dari terminal, keluar dengan kode bukan error
	// membingungkan.
	if *exitZero || cancelled {
		return
	}
	os.Exit(worst)
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

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

func main() {
	log.SetFlags(0)

	var (
		target   = flag.String("target", "", "URL target, contoh https://staging.example.com")
		outDir   = flag.String("out", "out", "direktori output")
		stem     = flag.String("name", "", "nama file output tanpa ekstensi (default: dari host target)")
		conc     = flag.Int("conc", 4, "request paralel")
		delay    = flag.Duration("delay", 250*time.Millisecond, "jeda minimal antar request")
		doProbe  = flag.Bool("probe", true, "verifikasi endpoint hasil ekstraksi JS (OPTIONS saja)")
		timeout  = flag.Duration("timeout", 3*time.Minute, "batas waktu total")
		quiet    = flag.Bool("quiet", false, "hanya cetak ringkasan singkat")
		noCol    = flag.Bool("no-color", false, "matikan warna (default: autodeteksi terminal)")
		ascii    = flag.Bool("ascii", false, "pakai karakter ASCII, bukan unicode")
		width    = flag.Int("width", 0, "lebar output kolom; 0 = autodeteksi (berguna di Termux)")
		showVer  = flag.Bool("version", false, "tampilkan versi lalu keluar")
		sarif    = flag.Bool("sarif", true, "tulis findings.sarif (SARIF 2.1.0) untuk CI/code scanning")
		exitZero = flag.Bool("exit-zero", false, "selalu keluar dengan kode 0 (untuk pemakaian manual)")
		compact  = flag.Bool("compact", false, "ringkas: batas daftar per kategori")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println(lumen.Banner())
		return
	}
	// Target boleh datang dari env var. Di HP, mengetik URL panjang di
	// keyboard virtual: lambat, dan gampang nekan
	//ENTER di tengah kata (yang terjadi ke kita: "-wi" + "dth"). Sekali set,
	// selamanya pakai nama pendek.
	if *target == "" {
		*target = os.Getenv("LUMEN_TARGET")
	}
	if *target == "" {
		flag.Usage()
		os.Exit(2)
	}

	u, err := url.Parse(*target)
	if err != nil || u.Host == "" {
		log.Fatalf("URL tidak valid: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		log.Fatalf("scheme harus http atau https, dapat %q", u.Scheme)
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

	host := u.Hostname()
	name := *stem
	if name == "" {
		name = sanitise(host)
	}

	if !*quiet {
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Ctrl-C menghentikan dengan rapi dan tetap menulis laporan yang sudah
	// terkumpul. Laporan parsial jauh lebih berguna daripada tidak ada.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\ndihentikan — menulis laporan parsial")
		cancel()
	}()

	start := time.Now()
	m := lumen.NewMapper(lumen.MapperConfig{
		Target: u, Conc: *conc, Delay: *delay,
	})
	m.Run(ctx)

	pages, eps, findings, stats := m.Snapshot()

	if *doProbe {
		probed := lumen.ProbeEndpoints(ctx, m, eps, lumen.ProbeOptions{Conc: *conc})
		// gabungkan status/flag dari probe ke endpoint asal
		byKey := map[string]lumen.Endpoint{}
		for _, e := range eps {
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
		eps = eps[:0]
		for _, e := range byKey {
			eps = append(eps, e)
		}
		// turning findings dari probe
		for _, e := range probed {
			if len(e.Flags) == 0 {
				continue
			}
			findings = append(findings, lumen.Finding{
				Kind:     "endpoint",
				Severity: lumen.FlagSeverity(e.Flags),
				Where:    e.Path,
				Detail:   fmt.Sprintf("%s -> %d %v", e.Method, e.Status, e.Flags),
			})
		}
	}

	findings = lumen.BySeverity(findings)

	// Kandidat OWASP + cakupan. Klasifikasi memakai sinyal statis, jadi
	// hasilnya sengaja disebut kandidat dan selalu disertai langkah
	// verifikasi — bukan "temuan terbukti".
	cands := lumen.Classify(eps, findings)
	cov := lumen.BuildCoverage(lumen.Report{Stats: stats})

	code := lumen.ExitCode(lumen.Report{Stats: stats}, cands)
	rep := lumen.Report{
		Target:      u.String(),
		GeneratedAt: time.Now().UTC(),
		DurationMS:  time.Since(start).Milliseconds(),
		Pages:       pages,
		Endpoints:   eps,
		Findings:    findings,
		ScopeDenied: m.Scope().Denied(),
		Stats:       stats,
		Candidates:  cands,
		Coverage:    cov,
	}

	jsonPath := filepath.Join(*outDir, name+".json")
	textPath := filepath.Join(*outDir, name+".txt")
	if err := lumen.SaveReport(jsonPath, textPath, rep, style, cands, cov, *compact || style.Width < 70); err != nil {
		log.Fatalf("gagal menulis laporan: %v", err)
	}

	// SARIF 2.1.0: format yang sudah dipahami GitHub code scanning, GitLab,
	// dan sebagian besar pipeline. Tanpa ini setiap adopter harus menulis
	// parser sendiri — dan pada praktiknya tidak ada yang mau.
	sarifPath := filepath.Join(*outDir, name+".sarif")
	if *sarif {
		if err := lumen.WriteSARIF(sarifPath, lumen.BuildSARIF(rep, cands, cov, code)); err != nil {
			log.Fatalf("gagal menulis SARIF: %v", err)
		}
	}

	fmt.Print(lumen.Render(rep, style, cands, cov, *compact || style.Width < 70))
	fmt.Print(lumen.Footer(jsonPath, textPath, style, sarifPath, *sarif))

	// Exit code hanya berarti kalau aman dipakai di pipeline; kalau human
	// yang menjalankan dari terminal, keluar dengan kode bukan error
	// membingungkan.
	if *exitZero {
		return
	}
	os.Exit(code)
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

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
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"lumen/internal/mapper"
	"lumen/internal/model"
	"lumen/internal/probe"
	"lumen/internal/report"
)

const version = "0.1.0"

func main() {
	log.SetFlags(0)

	var (
		target  = flag.String("target", "", "URL target, contoh https://staging.example.com")
		outDir  = flag.String("out", "out", "direktori output")
		stem    = flag.String("name", "", "nama file output tanpa ekstensi (default: dari host target)")
		conc    = flag.Int("conc", 4, "request paralel")
		delay   = flag.Duration("delay", 250*time.Millisecond, "jeda minimal antar request")
		doProbe = flag.Bool("probe", true, "verifikasi endpoint hasil ekstraksi JS (OPTIONS saja)")
		timeout = flag.Duration("timeout", 3*time.Minute, "batas waktu total")
		quiet   = flag.Bool("quiet", false, "hanya cetak ringkasan singkat")
	)
	flag.Usage = usage
	flag.Parse()

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

	host := u.Hostname()
	name := *stem
	if name == "" {
		name = sanitise(host)
	}

	if !*quiet {
		fmt.Printf("lumen %s\n", version)
		fmt.Printf("target   : %s\n", u.String())
		fmt.Printf("delay    : %s (konservatif by design)\n", *delay)
		fmt.Printf("probe    : %v (OPTIONS saja, tanpa perubahan state)\n", *doProbe)
		fmt.Printf("output   : %s\n\n", filepath.Join(*outDir, name))
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
	m := mapper.New(mapper.Config{
		Target: u, Conc: *conc, Delay: *delay,
	})
	m.Run(ctx)

	pages, eps, findings, stats := m.Snapshot()

	if *doProbe {
		probed := probe.Run(ctx, m, eps, probe.Options{Conc: *conc})
		// gabungkan status/flag dari probe ke endpoint asal
		byKey := map[string]model.Endpoint{}
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
			findings = append(findings, model.Finding{
				Kind:     "endpoint",
				Severity: probe.Severity(e.Flags),
				Where:    e.Path,
				Detail:   fmt.Sprintf("%s -> %d %v", e.Method, e.Status, e.Flags),
			})
		}
	}

	findings = report.BySeverity(findings)

	rep := model.Report{
		Target:      u.String(),
		GeneratedAt: time.Now().UTC(),
		DurationMS:  time.Since(start).Milliseconds(),
		Pages:       pages,
		Endpoints:   eps,
		Findings:    findings,
		ScopeDenied: m.Scope().Denied(),
		Stats:       stats,
	}

	jsonPath := filepath.Join(*outDir, name+".json")
	textPath := filepath.Join(*outDir, name+".txt")
	if err := report.Save(jsonPath, textPath, rep); err != nil {
		log.Fatalf("gagal menulis laporan: %v", err)
	}

	fmt.Print(report.Summary(rep))
	fmt.Printf("\noutput   : %s\n", jsonPath)
	fmt.Printf("          %s\n", textPath)
}

func usage() {
	fmt.Fprintf(os.Stderr, `lumen %s — pemeta permukaan aplikasi web untuk review keamanan

Pakai:
  lumen -target https://app.example.com
  lumen -target https://app.example.com -probe=false -delay 500ms
  lumen -target https://app.example.com -delay 1s -conc 2   # lebih konservatif

Hanya GET dan OPTIONS yang dikirim — tidak ada metode yang mengubah state.
Guard scope memblokir host di luar target dan mencatat penolakannya di laporan,
jadi invariansi "hanya menyentuh satu host" bisa diaudit dari output.

Alat ini tidak menyimpulkan kerentanan. Dia menunjuk hal yang menarik —
endpoint yang tidak ada di HTML, header yang hilang, kredensial yang ikut
ter-commit ke bundle. Penilaian tetap milik manusia.

`, version)
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

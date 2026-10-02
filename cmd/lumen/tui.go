package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"

	"github.com/arigustisj/lumen"
)

// isTerminal menandai apakah fd adalah terminal interaktif.
//
// Ini menentukan apakah dashboard boleh dipakai. Tanpa pemeriksaan ini,
// menjalankan lumen dengan output-nya di-pipe ke file akanRvancement
// menampilkan deretan escape ANSI di dalam file — salah dan membingungkan.
func isTerminal(f *os.File) bool { return isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()) }

// runTUI menjalankan dashboard untuk satu target.
//
// Prinsipnya: pemetaan sudah selesai di luar fungsi ini. TUI hanya
// menampilkan. Press "r" menjalankan pemetaan ulang lewat Runner, dan itu
// berjalan di goroutine tea sehingga tampilan tetap responsif.
func runTUI(name string, rep *lumen.Report, cands []lumen.Candidate, cov lumen.Coverage,
	compact bool, authz []lumen.AuthzReport,
	jsonPath, textPath, sarifPath string, writeSARIF bool,
	conc int, delay, timeout time.Duration, doProbe bool, j job,
) {

	m := lumen.NewTUIModel(rep.Target)
	m.SetRunner(func() (*lumen.Report, []lumen.AuthzReport, error) {
		return rescan(rep.Target, conc, delay, timeout, doProbe, j)
	})

	// Isi awal: hasil pemetaan yang sudah selesai.
	m.Seed(rep, cands, cov, authz)

	p := tea.NewProgram(m,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	if _, err := p.Run(); err != nil {
		// Dashboard gagal (bukan TTY, terminal aneh, dsb). Nama bukan
		// alasan untuk hilang begitu saja — laporan sudah ada di disk, tapi
		// orang tetap perlu melihat ringkasannya di layar.
		fmt.Fprintln(os.Stderr, "dashboard tidak bisa dibuka:", err)
		style := lumen.DetectStyle(os.Stdout)
		fmt.Print(lumen.Render(*rep, style, cands, cov, compact, authz))
		fmt.Print(lumen.Footer(jsonPath, textPath, style, sarifPath, writeSARIF))
		return
	}

	fmt.Println()
	style := lumen.DetectStyle(os.Stdout)
	fmt.Print(lumen.Footer(jsonPath, textPath, style, sarifPath, writeSARIF))
}

// rescan memetakan ulang target yang sama.
//
// Parameter diambil ulang dari flag, bukan disimpan di dalam TUI, supaya
// ada satu sumber kebenaran untuk konfigurasi pemetaan.
func rescan(target string, conc int, delay, timeout time.Duration,
	doProbe bool, j job) (*lumen.Report, []lumen.AuthzReport, error) {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()

	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, nil, fmt.Errorf("URL tidak valid: %s", target)
	}
	m := lumen.NewMapper(lumen.MapperConfig{Target: u, Conc: conc, Delay: delay})
	m.Run(ctx)

	pages, eps, findings, stats := m.Snapshot()
	if doProbe {
		applyProbe(ctx, m, &eps, &findings, conc)
	}
	findings = lumen.BySeverity(findings)
	cands := lumen.Classify(eps, findings)
	cov := lumen.BuildCoverage(lumen.Report{Stats: stats})

	rep := &lumen.Report{
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

	var az []lumen.AuthzReport
	if j.authz {
		tg := lumen.Target{Name: j.name, URL: j.url, Authz: true, Tokens: j.toks}
		names := tg.TokenNames()
		if len(names) >= 2 {
			ar, aerr := lumen.RunAuthz(ctx, tg.HTTPClient(), tg, eps,
				lumen.AuthzOptions{Baseline: "anon", Compare: names[1:]})
			if aerr == nil {
				for _, r := range ar.Results {
					if f := lumen.FindingFromAuthz(r); f != nil {
						rep.Findings = append(rep.Findings, *f)
					}
				}
				rep.Authz = &ar
				az = append(az, ar)
			}
		}
	}
	return rep, az, nil
}

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/arigustisj/lumen"
)

// Alur tanpa TUI: satu target, langsung pindai, tulis semua format.
func runPlain(j job, opts plainOpts) int {
	rep, authz := scanTarget(j, opts)
	store, err := lumen.OpenStore(opts.outDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gagal menyiapkan folder output:", err)
		return 1
	}
	run, err := store.SaveRun(rep, time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "gagal menyimpan laporan:", err)
	}
	base := filepath.Join(opts.outDir, run.File)
	if err := lumen.WriteMarkdown(strings.TrimSuffix(base, ".json")+".md",
		rep, rep.Candidates, rep.Coverage, run); err != nil {
		fmt.Fprintln(os.Stderr, "gagal menulis markdown:", err)
	}
	if opts.writeSARIF {
		if err := lumen.WriteSARIF(strings.TrimSuffix(base, ".json")+".sarif",
			lumen.BuildSARIF(*rep, rep.Candidates, rep.Coverage,
				lumen.ExitCode(*rep, rep.Candidates))); err != nil {
			fmt.Fprintln(os.Stderr, "gagal menulis SARIF:", err)
		}
	}

	style := lumen.DetectStyle(os.Stdout)
	if opts.compact || style.Width < 70 {
		if style.Width > 70 {
			style.Width = 70
		}
	}
	if !opts.quiet {
		fmt.Print(lumen.Render(*rep, style, rep.Candidates, rep.Coverage, opts.compact, authz))
		fmt.Print(lumen.Footer(base, strings.TrimSuffix(base, ".json")+".md",
			style, strings.TrimSuffix(base, ".json")+".sarif", opts.writeSARIF))
	}
	return 0
}

type plainOpts struct {
	outDir     string
	conc       int
	delay      time.Duration
	timeout    time.Duration
	doProbe    bool
	writeSARIF bool
	noDNSFix   bool
	compact    bool
	quiet      bool
}

// scanTarget memetakan satu target.
func scanTarget(j job, opts plainOpts) (*lumen.Report, []lumen.AuthzReport) {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	start := time.Now()

	u, err := url.Parse(j.url)
	if err != nil || u.Host == "" {
		return failedReport(j, fmt.Sprintf("URL tidak valid: %s", j.url), start), nil
	}

	dial, dnsNote := setupDNS(ctx, u, opts.noDNSFix)

	mcfg := lumen.MapperConfig{Target: u, Conc: opts.conc, Delay: opts.delay}
	if dial != nil {
		mcfg.DialContext = dial.DialContext
	}
	m := lumen.NewMapper(mcfg)
	m.Run(ctx)

	pages, eps, findings, stats := m.Snapshot()
	if opts.doProbe {
		applyProbe(ctx, m, &eps, &findings, opts.conc)
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
		RootError:   m.RootError(),
		DNSNote:     dnsNote,
		Stats:       stats,
		Candidates:  cands,
		Coverage:    cov,
	}

	var authz []lumen.AuthzReport
	if j.authz {
		if ar := runAuthzFor(ctx, j, eps, opts); ar != nil {
			for _, r := range ar.Results {
				if f := lumen.FindingFromAuthz(r); f != nil {
					rep.Findings = append(rep.Findings, *f)
				}
			}
			rep.Findings = lumen.BySeverity(rep.Findings)
			rep.Authz = ar
			authz = append(authz, *ar)
		}
	}
	return rep, authz
}

func runAuthzFor(ctx context.Context, j job, eps []lumen.Endpoint, opts plainOpts) *lumen.AuthzReport {
	tg := lumen.Target{Name: j.name, URL: j.url, Authz: true, Tokens: j.toks}
	names := tg.TokenNames()
	if len(names) < 2 {
		fmt.Fprintln(os.Stderr, "authz butuh minimal dua perspektif — dilewati")
		return nil
	}
	ar, err := lumen.RunAuthz(ctx, tg.HTTPClient(), tg, eps,
		lumen.AuthzOptions{Baseline: "anon", Compare: names[1:], DelayMS: int(opts.delay.Milliseconds())})
	if err != nil {
		fmt.Fprintln(os.Stderr, "authz:", err)
		return nil
	}
	return &ar
}

func failedReport(j job, msg string, start time.Time) *lumen.Report {
	return &lumen.Report{
		Target:      j.url,
		GeneratedAt: time.Now().UTC(),
		DurationMS:  time.Since(start).Milliseconds(),
		RootError:   msg,
		Stats:       map[string]int{},
		Findings: []lumen.Finding{{
			Kind:     "scan-gagal",
			Severity: lumen.SevHigh,
			Where:    j.url,
			Detail:   msg,
		}},
	}
}

// setupDNS menjalankan preflight; mengembalikan dialer kalau IP perlu dipin.
func setupDNS(ctx context.Context, u *url.URL, noFix bool) (*lumen.PinnedDialer, string) {
	if noFix {
		return nil, ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme != "https" {
			port = "80"
		}
	}
	res, err := lumen.PreflightDNS(ctx, host)
	if err != "" && len(res.IPs) == 0 {
		return nil, err
	}
	if res.Fallback && len(res.IPs) > 0 {
		return lumen.NewPinnedDialer(host, res.IPs[0], port),
			"DNS perangkat memblokir; scan memakai " + res.Used + " → " + res.IPs[0]
	}
	if res.Used == "sistem" && len(res.IPs) > 0 {
		return nil, "DNS: " + strings.Join(res.IPs, ", ")
	}
	return nil, ""
}

// ── TUI: beranda → riwayat → laporan ───────────────────────────────────────

// shell adalah model luar yang menyatukan beranda, laporan, dan status scan.
type shell struct {
	store   *lumen.Store
	home    *lumen.HomeModel
	report  *lumen.TUIModel
	opts    plainOpts
	quit    bool
	pending *job
	notice  string
}

func newShell(opts plainOpts) (*shell, error) {
	store, err := lumen.OpenStore(opts.outDir)
	if err != nil {
		return nil, err
	}
	return &shell{store: store, home: lumen.NewHomeModel(store), opts: opts}, nil
}

func (s *shell) Init() tea.Cmd { return nil }

func (s *shell) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.home.UpdateSize(msg.Width, msg.Height)
		if s.report != nil {
			mm, _ := s.report.Update(msg)
			s.report = mm.(*lumen.TUIModel)
		}
		return s, nil

	case tea.KeyMsg:
		k := msg.String()
		// Saat laporan terbuka, tombol yang tidak dipakai panel diteruskan
		// ke beranda supaya "esc" selalu jalan.
		if s.report != nil && !s.report.Quit() {
			if k == "esc" || k == "q" {
				if s.report.Quit() {
					return s, tea.Quit
				}
				s.report = nil
				s.notice = "kembali ke daftar"
				return s, nil
			}
			mm, _ := s.report.Update(msg)
			s.report = mm.(*lumen.TUIModel)
			return s, nil
		}
		if k == "ctrl+c" {
			s.quit = true
			return s, tea.Quit
		}
		act := s.home.Update(msg)
		switch {
		case act.Kind == "quit":
			s.quit = true
			return s, tea.Quit
		case act.Kind == "newscan":
			u := normaliseTarget(act.Target)
			j := job{url: u, name: hostOf(u)}
			s.pending = &j
			s.notice = "memindai " + u
			return s, s.runCmd(j)
		case act.Kind == "open" && act.Run != nil:
			rep, err := s.store.LoadRun(*act.Run)
			if err != nil {
				s.home.SetStatus("gagal membuka: " + err.Error())
				return s, nil
			}
			m := s.home.LoadedReport(rep, rep.Candidates, rep.Coverage, nil)
			mm, _ := m.Update(tea.WindowSizeMsg{Width: s.home.Width(), Height: s.home.Height()})
			s.report = mm.(*lumen.TUIModel)
			return s, nil
		}
		return s, nil

	case doneMsg:
		s.pending = nil
		s.home.Reload()
		rep, authz := msg.rep, msg.authz
		run, err := s.store.SaveRun(rep, msg.at)
		if err != nil {
			s.home.SetStatus("gagal menyimpan: " + err.Error())
			return s, nil
		}
		base := filepath.Join(s.opts.outDir, run.File)
		_ = lumen.WriteMarkdown(strings.TrimSuffix(base, ".json")+".md",
			rep, rep.Candidates, rep.Coverage, run)
		if s.opts.writeSARIF {
			_ = lumen.WriteSARIF(strings.TrimSuffix(base, ".json")+".sarif",
				lumen.BuildSARIF(*rep, rep.Candidates, rep.Coverage,
					lumen.ExitCode(*rep, rep.Candidates)))
		}
		m := lumen.NewTUIModel(rep.Target)
		m.Seed(rep, rep.Candidates, rep.Coverage, authz)
		mm, _ := m.Update(tea.WindowSizeMsg{Width: s.home.Width(), Height: s.home.Height()})
		s.report = mm.(*lumen.TUIModel)
		return s, nil

	case failMsg:
		s.pending = nil
		s.home.SetStatus("scan gagal: " + doneMsgOrFail(msg))
		return s, nil
	}
	return s, nil
}

func doneMsgOrFail(m tea.Msg) string {
	if f, ok := m.(failMsg); ok {
		return f.err.Error()
	}
	return ""
}

// doneMsg memberitahu loop TUI bahwa pemetaan selesai.
type doneMsg struct {
	rep   *lumen.Report
	authz []lumen.AuthzReport
	at    time.Time
}

type failMsg struct{ err error }

// runCmd menjalankan pemetaan di luar loop render.
//
// Pemetaan adalah pekerjaan jaringan yang bisa memakan puluhan detik. Kalau
// dijalankan di dalam Update, tampilan membeku dan pengguna menyimpulkan
// prosesnya hang — persis yang terjadi kalau ini keliru.
func (s *shell) runCmd(j job) tea.Cmd {
	opts := s.opts
	return func() tea.Msg {
		rep, authz := scanTarget(j, opts)
		if rep.RootError == "" && len(rep.Pages) == 0 {
			return failMsg{err: fmt.Errorf("tidak ada halaman yang bisa diambil")}
		}
		return doneMsg{rep: rep, authz: authz, at: time.Now()}
	}
}

func (s *shell) View() string {
	if s.quit {
		return ""
	}
	if s.report != nil {
		return s.report.View()
	}
	if s.pending != nil {
		return s.home.ViewScanning(s.pending.url)
	}
	return s.home.View() + "\n" + s.home.Footer()
}

// normaliseTarget menambahkan skema bila lupa diketik.
func normaliseTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return "https://" + s
	}
	return s
}

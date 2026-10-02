// Package mapper menjalankan crawl danqueurisan temuan.
//
// Semua request outbound WAJIB lewat sc.Limiter dan di-check sc.Scope lebih
// dulu. Kalau ada satu jalur yang melewatkan salah satu dari keduanya, seluruh
// jaminan "hanya menyentuh satu host" jadi tidak berlaku.
package lumen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// maxBodyBytes membatasi memori: 4MB cukup untuk bundle besar, dan
	// bounding-nya mencegah satu file aneh sucking up RAM.
	maxBodyBytes = 4 << 20
	maxPages     = 400
	maxBundles   = 120
	maxRedirs    = 8
	ua           = "lumen/1.0 (authorized-security-review)"
)

// Config adalah parameter crawler.
type MapperConfig struct {
	Target  *url.URL
	Conc    int
	Delay   time.Duration
	MaxBody int
}

type Mapper struct {
	sc   *Scope
	lim  *Limiter
	cfg  MapperConfig
	http *http.Client

	queue chan string
	wg    sync.WaitGroup

	mu        sync.Mutex
	seen      map[string]bool
	jsSeen    map[string]bool
	stats     map[string]int
	pages     []Page
	endpoints map[string]Endpoint
	findings  []Finding
	// root adalah URL awal pemetaan, dicatat terpisah supaya kegagalannya
	// bisa dibedakan dari kegagalan halaman lain.
	root string
	// rootErr menyimpan kegagalan pengambilan halaman pertama. Tanpa ini,
	// scan yang gagal total terlihat sama persis dengan scan yang berhasil
	// tapi memang tidak menemukan apa pun — dan orang menyimpulkan situsnya
	// aman karena laporan kosong.
	rootErr string
}

// RootError mengembalikan kegagalan pengambilan halaman awal, atau kosong
// kalau halaman awal sempat TERambil.
func (m *Mapper) RootError() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rootErr
}

// IsRoot menandai URL sebagai titik awal pemetaan.
func (m *Mapper) IsRoot(u string) bool { return u == m.cfg.Target.String() || u == m.cfg.Target.Host }

func NewMapper(cfg MapperConfig) *Mapper {
	if cfg.Conc < 1 {
		cfg.Conc = 4
	}
	if cfg.Delay <= 0 {
		cfg.Delay = 250 * time.Millisecond
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = maxBodyBytes
	}
	m := &Mapper{
		sc:        NewScope(cfg.Target),
		lim:       NewLimiter(cfg.Delay),
		cfg:       cfg,
		queue:     make(chan string, maxPages*2),
		seen:      map[string]bool{},
		jsSeen:    map[string]bool{},
		stats:     map[string]int{},
		endpoints: map[string]Endpoint{},
	}
	m.http = &http.Client{
		Timeout: 25 * time.Second,
		// Redirect boleh, tapi tidak keluar scope. Tanpa guard di sini,
		// satu 302 ke pihak ketiga sudah cukup untuk keluar dari target.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !m.sc.Allows(req.URL) {
				return http.ErrUseLastResponse
			}
			if len(via) > maxRedirs {
				return fmt.Errorf("terlalu banyak redirect")
			}
			return nil
		},
	}
	return m
}

func (m *Mapper) bump(k string) {
	m.mu.Lock()
	m.stats[k]++
	m.mu.Unlock()
}

func (m *Mapper) finding(kind string, sev Severity, where, detail string) {
	m.mu.Lock()
	m.findings = append(m.findings, Finding{
		Kind: kind, Severity: sev, Where: where, Detail: detail,
	})
	m.mu.Unlock()
}

func (m *Mapper) endpoint(e Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := e.Method + " " + e.Path
	if _, dup := m.endpoints[key]; !dup {
		m.endpoints[key] = e
	}
}

// Scope exposes guard supaya caller bisa reuse untuk probing.
func (m *Mapper) Scope() *Scope { return m.sc }

func (m *Mapper) Limiter() *Limiter { return m.lim }

func (m *Mapper) Target() *url.URL { return m.cfg.Target }

// Run melakukan crawl sampai tidak ada lagi URL yang belum dilihat.
//
// Queue ditutup setelah seluruh antrean selesai rather than setelah durasi
// tertentu: crawler yang berhenti tepat di tengah hanya menghasilkan laporan
// yang terlihat lengkap padahal belum.
func (m *Mapper) Run(ctx context.Context) {
	// start dicatat eksplisit supaya kegagalan di halaman awal bisa
	// dibedakan dari kegagalan halaman mana pun. Tanpa penanda ini, scan
	// yang gagal total terlihat sama dengan scan yang berhasil tetapi
	// memang tidak menemukan apa pun.
	start := Canonical(m.cfg.Target.String())
	m.mu.Lock()
	m.root = start
	m.mu.Unlock()

	m.markSeen(start)
	m.enqueue(start)

	// closer menutup queue setelah counterinflight mencapai nol.
	go func() {
		m.wg.Wait()
		close(m.queue)
	}()

	var wgWorkers sync.WaitGroup
	for i := 0; i < m.cfg.Conc; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			for u := range m.queue {
				if ctx.Err() != nil {
					m.done()
					continue // draining, supaya wg tetap turun
				}
				m.crawlOne(ctx, u)
				m.done()
			}
		}()
	}
	wgWorkers.Wait()
}

// done menandai satu item selesai diproses.
func (m *Mapper) done() { m.wg.Done() }

func (m *Mapper) enqueue(u string) {
	// Add dulu, baru kirim: kalau queue penuh dan item dibuang, wg harus
	// dikembalikan supaya closer tidak menunggu selamanya.
	m.wg.Add(1)
	select {
	case m.queue <- u:
		m.bump("queued")
	default:
		m.bump("queue-penuh")
		m.wg.Done()
	}
}

// markSeen mencatat URL sebagai sudah dipesan agar tidak di-crawl dua kali.
func (m *Mapper) markSeen(u string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[u] || len(m.seen) >= maxPages {
		return false
	}
	m.seen[u] = true
	return true
}

func (m *Mapper) crawlOne(ctx context.Context, raw string) {
	code, body, hdr, err := m.get(ctx, raw)
	if err != nil {
		m.mu.Lock()
		isRoot := raw == m.root
		if isRoot {
			m.rootErr = err.Error()
		}
		m.mu.Unlock()
		m.bump("error")
		// Kegagalan di halaman awal adalah kegagalan scan, bukan temuan
		// ringan. Menaruhnya sebagai "info" membuatnya hilang di antara
		// bar komposisi.
		sev := SevInfo
		if isRoot {
			sev = SevHigh
		}
		m.finding("scan-gagal", sev, raw, "gagal diambil: "+err.Error())
		return
	}
	m.bump("crawled")

	ct := hdr.Get("Content-Type")
	isHTML := strings.Contains(ct, "text/html")
	pg := Page{
		URL: raw, Status: code, ContentLen: len(body), IsHTML: isHTML,
		Title: Title(body),
	}

	m.checkHeaders(&pg, hdr, raw)
	m.checkCookies(&pg, hdr, raw)

	pg.QueryKeys = QueryKeys(raw)
	if len(pg.QueryKeys) > 0 {
		m.finding("query", SevLow, raw,
			"query param: "+strings.Join(pg.QueryKeys, ", "))
	}
	pg.FormFields = FormFields(body)
	if len(pg.FormFields) > 0 {
		m.finding("form", SevInfo, raw,
			"form field: "+strings.Join(pg.FormFields, ", "))
	}

	m.mu.Lock()
	m.pages = append(m.pages, pg)
	m.mu.Unlock()

	m.endpoint(Endpoint{
		Method: "GET", Path: raw, Origin: OriginHTML,
		Status: code, Title: pg.Title,
	})

	if !isHTML {
		return
	}
	for _, fw := range DetectFramework(body) {
		m.finding("tech", SevInfo, raw, "framework: "+fw)
	}
	m.followLinks(raw, body)
	m.followScripts(ctx, raw, body)
	m.followForms(raw, body)
}

func (m *Mapper) followLinks(page, body string) {
	for _, l := range Links(body) {
		abs, ok := AbsResolve(page, l)
		if !ok {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil || !m.sc.Allows(u) {
			continue
		}
		abs = Canonical(abs)
		if !m.markSeen(abs) {
			continue
		}
		m.enqueue(abs)
	}
}

func (m *Mapper) followScripts(ctx context.Context, page, body string) {
	for _, s := range Scripts(body) {
		abs, ok := AbsResolve(page, s)
		if !ok {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil || !m.sc.Allows(u) {
			continue
		}
		m.mu.Lock()
		first := !m.jsSeen[abs]
		if first {
			m.jsSeen[abs] = true
		}
		n := m.stats["bundle"]
		m.mu.Unlock()
		if !first || n >= maxBundles {
			continue
		}
		m.crawlBundle(ctx, abs)
	}
}

func (m *Mapper) crawlBundle(ctx context.Context, src string) {
	code, body, _, err := m.get(ctx, src)
	if err != nil || code != 200 {
		return
	}
	m.bump("bundle")

	sum := sha256.Sum256([]byte(body))
	hash := hex.EncodeToString(sum[:])[:12]
	m.finding("bundle", SevInfo, src,
		fmt.Sprintf("JS %d KB sha256:%s", len(body)/1024, hash))

	res := AnalyzeJS(src, body)
	for _, e := range res.Endpoints {
		m.endpoint(e)
	}
	for _, t := range res.Tech {
		sev := SevInfo
		kind := "tech"
		switch strings.ToLower(t) {
		case "gorm", "prisma", "sequelize", "knex":
			// ORM terdeteksi = ada lapisan parameterisasi. Informasi berguna
			// untuk memutuskan mana yang perlu dicek manual (raw query).
			kind, sev = "orm-terdeteksi", SevLow
		}
		m.finding(kind, sev, src, "stack: "+t)
	}
	for _, s := range res.Secrets {
		m.finding("secret-di-bundle", SevHigh, src,
			"pola kredensial "+s.Kind+" = "+s.Sample+" (rotasi bila nyata)")
	}
}

func (m *Mapper) followForms(page, body string) {
	for _, a := range FormActions(body) {
		abs, ok := AbsResolve(page, a)
		if !ok {
			continue
		}
		if u, err := url.Parse(abs); err != nil || !m.sc.Allows(u) {
			continue
		}
		m.endpoint(Endpoint{
			Method: "POST", Path: abs, Origin: OriginHTML, Source: page,
		})
	}
}

var securityHeaders = []struct {
	Name string
	Sev  Severity
	Note string
}{
	{"Strict-Transport-Security", SevHigh, "hSTS tidak ada"},
	{"Content-Security-Policy", SevHigh, "CSP tidak ada"},
	{"X-Frame-Options", SevMedium, "bisa di-embed iframe (clickjacking)"},
	{"Referrer-Policy", SevLow, "referrer policy tidak ada"},
}

func (m *Mapper) checkHeaders(pg *Page, hdr http.Header, raw string) {
	pg.Headers = map[string]string{}
	for _, sh := range securityHeaders {
		if v := hdr.Get(sh.Name); v == "" {
			m.finding("header", sh.Sev, raw, sh.Name+" tidak ada — "+sh.Note)
		} else {
			pg.Headers[sh.Name] = v
		}
	}
	if v := hdr.Get("X-Content-Type-Options"); v != "" {
		pg.Headers["X-Content-Type-Options"] = v
	}
	if v := hdr.Get("Server"); v != "" {
		pg.Headers["Server"] = v
	}
	if po := hdr.Get("Permissions-Policy"); po != "" {
		pg.Headers["Permissions-Policy"] = po
	}

	acao := hdr.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		m.finding("cors", SevHigh, raw,
			"Access-Control-Allow-Origin: * — origin mana pun bisa membaca respons")
	} else if acao != "" {
		pg.Headers["Access-Control-Allow-Origin"] = acao
	}
	if hdr.Get("Access-Control-Allow-Credentials") == "true" && acao != "" {
		detail := "CORS allow-credentials dengan origin eksplisit"
		sev := SevHigh
		if acao == "*" {
			detail += " (dan origin-nya wildcard — paling berbahaya)"
		}
		m.finding("cors", sev, raw, detail)
	}
}

// checkCookies mengisi pg secara langsung.
//
// Dulu menulis ke m.pages[len(m.pages)-1], yang salah: dengan beberapa worker
// paralel, halaman lain bisa sudah masuk lebih dulu sehingga cookie
// menempel ke halaman yang bukan miliknya — dan kalau slice masih kosong,
// terjadi panic index out of range.
func (m *Mapper) checkCookies(pg *Page, hdr http.Header, raw string) {
	for _, ck := range hdr.Values("Set-Cookie") {
		name := ck
		if i := strings.Index(ck, "="); i > 0 {
			name = ck[:i]
		}
		pg.Cookies = append(pg.Cookies, name)

		lower := strings.ToLower(ck)
		if !strings.Contains(lower, "httponly") {
			m.finding("cookie", SevLow, raw, "cookie tanpa HttpOnly: "+name)
		}
		if !strings.Contains(lower, "secure") && strings.HasPrefix(raw, "https://") {
			m.finding("cookie", SevMedium, raw, "cookie tanpa flag Secure: "+name)
		}
		if strings.Contains(lower, "samesite=none") {
			m.finding("cookie", SevLow, raw,
				"SameSite=None: cookie ikut terkirim lintas situs: "+name)
		}
	}
}

func (m *Mapper) get(ctx context.Context, u string) (int, string, http.Header, error) {
	m.lim.Wait()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	resp, err := m.http.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(m.cfg.MaxBody)))
	if err != nil {
		return resp.StatusCode, "", resp.Header, err
	}
	return resp.StatusCode, string(b), resp.Header, nil
}

// Snapshot mengembalikan hasil yang sudah terurut. Diurutkan supaya dua scan
// atas target yang sama menghasilkan file yang bisa di-diff dengan bersih.
func (m *Mapper) Snapshot() ([]Page, []Endpoint, []Finding, map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pages := make([]Page, len(m.pages))
	copy(pages, m.pages)
	sort.Slice(pages, func(i, j int) bool { return pages[i].URL < pages[j].URL })

	eps := make([]Endpoint, 0, len(m.endpoints))
	for _, e := range m.endpoints {
		eps = append(eps, e)
	}
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Path != eps[j].Path {
			return eps[i].Path < eps[j].Path
		}
		return eps[i].Method < eps[j].Method
	})

	fs := make([]Finding, len(m.findings))
	copy(fs, m.findings)
	// Temuan berat lebih dulu: tinggi → sedang → rendah → info. Dengan begitu
	// output ~/.txt langsung terbaca dari atas tanpa perlu scroll.
	rank := map[Severity]int{SevHigh: 0, SevMedium: 1, SevLow: 2, SevInfo: 3}
	sort.SliceStable(fs, func(i, j int) bool { return rank[fs[i].Severity] < rank[fs[j].Severity] })

	stats := make(map[string]int, len(m.stats))
	for k, v := range m.stats {
		stats[k] = v
	}
	return pages, eps, fs, stats
}

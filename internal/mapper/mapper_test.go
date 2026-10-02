package mapper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"lumen/internal/model"
)

// fakeSPA meniru aplikasi React: HTML-nya nyaris kosong, semua rute API ada
// di dalam bundle. Inilah kasus yang membuat crawler biasa tidak berguna.
const fakeHTML = `<!doctype html><html><head><title>App</title>
<script src="/static/app.js"></script>
<script src="https://cdn.evil.net/tracker.js"></script>
</head><body><div id="root"></div>
<a href="/about">about</a>
<a href="https://other.example.com/rahasia">luar</a>
</body></html>`

const fakeJS = `
const api=axios.create({baseURL:"/api"});
api.get("/api/users/me");
api.post("/api/orders/checkout",{items:[]});
api({method:"DELETE",url:"/api/admin/users/42"});
const k={apiKey:"AKIAIOSFODNN7EXAMPLE12345"};
fetch("https://telemetry.evil.net/ping");
`

func TestSPAEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Set-Cookie", "session=abc")
			_, _ = w.Write([]byte(fakeHTML))
		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(fakeJS))
		case "/about":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><title>About</title></head><body>tentang</body></html>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	m := New(Config{Target: u, Conc: 2, Delay: time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	m.Run(ctx)

	pages, eps, findings, stats := m.Snapshot()

	// 1. Bundle harus terbaca.
	if stats["bundle"] == 0 {
		t.Fatal("bundle JS tidak diambil — ini kemampuan utama alat ini")
	}

	// 2. Rute API yang TIDAK ADA di HTML harus ditemukan lewat bundle.
	paths := map[string]model.Endpoint{}
	for _, e := range eps {
		if e.Origin == model.OriginJS {
			paths[e.Path] = e
		}
	}
	for _, want := range []string{"/api/users/me", "/api/orders/checkout", "/api/admin/users/42"} {
		if _, ok := paths[want]; !ok {
			t.Errorf("endpoint %q tidak ditemukan dari bundle", want)
		}
	}
	if got := paths["/api/orders/checkout"].Method; got != "POST" {
		t.Errorf("metode /api/orders/checkout = %q, mau POST", got)
	}

	// 3. Halaman harus ter-crawl lewat link internal.
	var sawAbout bool
	for _, p := range pages {
		if strings.HasSuffix(p.URL, "/about") {
			sawAbout = true
		}
	}
	if !sawAbout {
		t.Error("halaman /about tidak ter-crawl")
	}

	// 4. Host luar harus DITOLAK, dan keputusannya harus terlihat.
	denied := m.Scope().Denied()
	if len(denied) == 0 {
		t.Error("link/script ke host luar tidak dicatat sebagai ditolak — guard tidak bekerja")
	}
	for _, d := range denied {
		if !strings.Contains(d, "evil.net") && !strings.Contains(d, "other.example.com") {
			t.Errorf("Denied() = %q, di luar daftar host yang seharusnya dicoba", d)
		}
	}
	// Tidak boleh ada halaman dari host luar.
	for _, p := range pages {
		if !strings.Contains(p.URL, u.Host) {
			t.Errorf("halaman dari luar scope ikut ter-crawl: %s", p.URL)
		}
	}

	// 5. Kredensial tertanam harus dilaporkan (dan disamarkan).
	var secretFound bool
	for _, f := range findings {
		if f.Kind == "secret-di-bundle" {
			secretFound = true
			if strings.Contains(f.Detail, "AKIAIOSFODNN7EXAMPLE12345") {
				t.Error("nilai kredensial utuh bocor ke laporan")
			}
		}
	}
	if !secretFound {
		t.Error("apiKey di bundle tidak dilaporkan")
	}

	// 6. Cookie tanpa flag harus ditandai.
	var cookieFlag bool
	for _, f := range findings {
		if f.Kind == "cookie" {
			cookieFlag = true
		}
	}
	if !cookieFlag {
		t.Error("cookie tanpa HttpOnly/Secure tidak ditandai")
	}
}

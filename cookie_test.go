package lumen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Server dengan sesi berbasis cookie, rotasi sesi, dan token CSRF.
//
// Tiga hal ini ada di aplikasi sungguhan dan ketiganya membuat pengujian
// header-only gagal secara diam-diam:
//
//  1. Autentikasi lewat cookie HttpOnly, bukan header.
//  2. Server merotasi cookie sesi tiap response (banyak framework begitu).
//  3. Cookie CSRF terpisah yang wajib dikirim balik sebagai header.
//
// Kalau pengujian tidak menangani ketiganya, ia akan menyimpulkan
// "auth tidak aktif" pada aplikasi yang sebenarnya Updates perfect.
type cookieSrv struct {
	// guarded = pemeriksaan kepemilikan benar.
	guarded bool
	// rotateSession = server mengganti nilai cookie sesi tiap response.
	rotateSession bool
	seen          map[string]int
}

func (s *cookieSrv) serve() http.Handler {
	// Peta cookie sesi ke username.
	//
	// Nilai cookie dan nilai yang dipakai di konfigurasi didaftarkan di sini
	// supaya sesuai dengan cara kerja nyata: nilai cookie disalin dari
	// peramban, bukan diterbitkan oleh tool.
	sess := map[string]string{
		"alice-fixed-1": "alice",
		"bob-fixed-1":   "bob",
	}
	objs := map[string]map[string]any{
		"1001": {"id": 1001, "owner": "alice", "item": "laptop", "note": "PIN alice: 4417"},
		"1002": {"id": 1002, "owner": "alice", "item": "monitor", "note": "alamat alice"},
		"2001": {"id": 2001, "owner": "bob", "item": "sepatu", "note": "alamat bob"},
	}
	listOf := map[string][]string{"alice": {"1001", "1002"}, "bob": {"2001"}}
	counter := 0

	cur := func(r *http.Request) string {
		c, err := r.Cookie("session")
		if err != nil {
			return ""
		}
		return sess[c.Value]
	}
	csrf := func(r *http.Request) string {
		c, err := r.Cookie("csrf")
		if err != nil {
			return ""
		}
		return c.Value
	}
	issue := func(w http.ResponseWriter, user string) {
		counter++
		v := fmt.Sprintf("sess-%s-%d", user, counter)
		sess[v] = user
		http.SetCookie(w, &http.Cookie{Name: "session", Value: v, Path: "/", HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "csrf", Value: "csrf-" + user, Path: "/"})
	}
	// Otentikasi cookie biasa: kalau ada sesi, cookie CSRF juga harus cocok
	// dengan cookie — persis seperti framework modern.
	gate := func(w http.ResponseWriter, r *http.Request) bool {
		u := cur(r)
		if u == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		if csrf(r) == "" || r.Header.Get("X-CSRF-Token") != csrf(r) {
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u := r.URL.Query().Get("u")
		if u == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		issue(w, u)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ok": u})
	})
	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		u := cur(r)
		if s.rotateSession {
			issue(w, u) // rotasi: cookie lama harus terus jalan
		}
		var items []map[string]any
		for _, id := range listOf[u] {
			items = append(items, objs[id])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"items": items})
	})
	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		if !gate(w, r) {
			return
		}
		u := cur(r)
		if s.rotateSession {
			issue(w, u)
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		o, ok := objs[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if s.guarded && o["owner"] != u {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(o)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!doctype html><html><body>root</body></html>`)
	})
	return mux
}

func cookieTarget(t *testing.T, base string) Target {
	t.Helper()
	// Nilai persis seperti yang copied dari browser.
	return Target{
		Name:  "cookie",
		URL:   base,
		Authz: true,
		Tokens: Tokens{
			"anon":  "",
			"alice": "Cookie: session=alice-fixed-1; csrf=csrf-alice",
			"bob":   "Cookie: session=bob-fixed-1; csrf=csrf-bob",
		},
	}
}

func cookieEndpoints() []Endpoint {
	return []Endpoint{{Path: "/api/orders", Method: http.MethodGet}}
}

// TestSesiCookieTidakBocorAntarPerspektif — ini regression test untuk bug
// yang paling merusak: kalau alice dan bob memakai jar yang sama, request
// bob bisa membawa cookie alice dan tool melaporkan "terjaga" untuk
// pengujian yang sebenarnya tidak menguji apa pun.
func TestSesiCookieTidakBocorAntarPerspektif(t *testing.T) {
	srv := httptest.NewServer((&cookieSrv{guarded: true, rotateSession: true}).serve())
	defer srv.Close()

	// Server ini menolak sesi yang tidak dikenal, jadi cookie alice yang
	// dibawa ke request bob akan menghasilkan 401 — bukan data.
	tg := cookieTarget(t, srv.URL)
	rep := ProbeOwnership(context.Background(), tg.HTTPClient(), tg,
		cookieEndpoints(), "alice", "bob", 0)

	if len(rep.Swaps) == 0 {
		t.Fatalf("tidak ada yang diuji: list=%v unknown=%d", rep.ListsUsed, rep.Unreadable)
	}
	if rep.Proven != 0 {
		for _, sw := range rep.Swaps {
			if sw.Verdict == OwnerLeak {
				t.Errorf("server butuh pengujian yang benar; %s dilaporkan bocor: %s", sw.ObjectID, sw.Note)
			}
		}
	}
	if rep.Guarded == 0 {
		t.Errorf("server terjaga harus menghasilkan 'terjaga', got unknown=%d unknown2=%d", rep.Guarded, rep.Unreadable)
	}
}

// TestSesiCookieMenangkapKebocoran — cookie yang benar-benar diuji harus bisa
// menemukan kebocoran. Ini memastikan fixture di atas bukan selalu aman.
func TestSesiCookieMenangkapKebocoran(t *testing.T) {
	srv := httptest.NewServer((&cookieSrv{guarded: false, rotateSession: true}).serve())
	defer srv.Close()

	tg := cookieTarget(t, srv.URL)
	rep := ProbeOwnership(context.Background(), tg.HTTPClient(), tg,
		cookieEndpoints(), "alice", "bob", 0)

	if rep.Proven == 0 {
		for _, sw := range rep.Swaps {
			t.Logf("[%s] %s — %s", sw.Verdict, sw.ObjectID, sw.Note)
		}
		t.Fatal("server tanpa cek ownership harus menghasilkan kebocoran terbukti")
	}
}

// TestCSRFDiteruskanOtomatis — cookie CSRF harus berakhir sebagai header.
// Tanpa ini, setiap request ditolak 403 dan hasilnya akan salah dibaca
// sebagai "guard bekerja".
func TestCSRFDiteruskanOtomatis(t *testing.T) {
	srv := httptest.NewServer((&cookieSrv{guarded: true, rotateSession: true}).serve())
	defer srv.Close()

	tg := cookieTarget(t, srv.URL)
	// Dijalankan tanpa NoShellProbe supaya shell fetch juga memakai jar.
	rep, err := RunAuthz(context.Background(), tg.HTTPClient(), tg,
		[]Endpoint{{Path: "/api/orders", Method: http.MethodGet}},
		AuthzOptions{Baseline: "alice", Compare: []string{"bob"}})
	if err != nil {
		t.Fatalf("RunAuthz: %v", err)
	}
	if len(rep.Results) == 0 {
		t.Fatal("tidak ada hasil")
	}
	v := rep.Results[0].Views["alice"]
	if v.Status < 200 || v.Status >= 300 {
		t.Errorf("alice harusnya 200, dapat %d (err=%q) — CSRF kemungkinan tidak diteruskan", v.Status, v.Error)
	}
}

// TestParseCookieHeader menguji parsing "a=b; c=d".
func TestParseCookieHeader(t *testing.T) {
	ck := parseCookieHeader("session=abc; csrf=xyz; Secure; empty=")
	got := map[string]string{}
	for _, c := range ck {
		got[c.Name] = c.Value
	}
	if got["session"] != "abc" || got["csrf"] != "xyz" {
		t.Errorf("cookie tidak terparse benar: %v", got)
	}
	if _, ok := got["empty"]; ok {
		t.Error("cookie tanpa nilai harus diabaikan")
	}
	if len(ck) != 2 {
		t.Errorf("harusnya 2 cookie yang bisa dikirim, dapat %d", len(ck))
	}
}

// TestClientsPerPerspektifTerpisah memastikan dua perspektif tidak pernah
// berbagi client — kebocoran yang harus dicek secara langsung.
func TestClientsPerPerspektifTerpisah(t *testing.T) {
	tg := Target{Name: "t", URL: "https://x.test",
		Tokens: Tokens{"alice": "Cookie: session=a", "bob": "Cookie: session=b"}}
	c := NewClients(tg, []string{"alice", "bob"}, tg.HTTPClient())
	a, b := c.For("alice"), c.For("bob")
	if a == b {
		t.Fatal("alice dan bob memakai client yang sama — sesi bisa bocor")
	}
	if c.For("alice") != a {
		t.Error("client harus stabil antar panggilan (jar harus bertahan)")
	}
	if c.For("anon") == a {
		t.Error("anon tidak seharusnya memakai client bersesi")
	}
}

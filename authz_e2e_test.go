package lumen

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// srvWithHoles adalah server uji yang meniru pola yang sering ditemukan di
// aplikasi nyata:
//
//	/api/user/profile  → terlindungi (401 untuk anonim)
//	/admin/desa_wisata → terbuka untuk semua
//	/api/public/info   → publik, dan isinya sama untuk semua orang
//	/api/account/:id   → 200 untuk semua akun, isi berbeda per akun
//	/api/health        → 200 tanpa token, tapi isinya beda antar akun (noise)
func srvWithHoles() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/user/profile":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"nama":"budi","id":1}`)
		case "/admin/desa_wisata":
			// Tidak ada cek sama sekali — ini yang harus tertangkap.
			fmt.Fprint(w, `{"items":[],"total":0}`)
		case "/api/public/info":
			fmt.Fprint(w, `{"app":"parama","version":"1.0"}`)
		case "/api/account/1":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if auth == "Bearer token-a" {
				fmt.Fprint(w, `{"owner":"a","saldo":100}`)
			} else {
				fmt.Fprint(w, `{"owner":"b","saldo":900}`)
			}
		case "/api/account/2":
			if auth == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"owner":"a","saldo":100}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func testTarget(t *testing.T) (Target, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(srvWithHoles())
	t.Cleanup(srv.Close)
	return Target{
		Name: "uji",
		URL:  srv.URL,
		Tokens: Tokens{
			"anon":      "",
			"as_user_a": "Bearer token-a",
			"as_user_b": "Bearer token-b",
		},
	}, srv
}

// TestAuthzEndToEndMemSemuaTigaKelas — memastikan ketiga bentuk vonis yang
// bisa ditemukan benar-benar muncul pada server yang meniru celah nyata.
func TestAuthzEndToEndMemSemuaTigaKelas(t *testing.T) {
	tg, _ := testTarget(t)
	eps := []Endpoint{
		{Path: "/api/user/profile", Method: "GET"},
		{Path: "/admin/desa_wisata", Method: "GET"},
		{Path: "/api/public/info", Method: "GET"},
		{Path: "/api/account/:id", Method: "GET"},
		{Path: "/api/account/1", Method: "GET"},
	}
	rep, err := RunAuthz(context.Background(), tg.HTTPClient(), tg, eps,
		AuthzOptions{Baseline: "anon", Compare: []string{"as_user_a", "as_user_b"}})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.Path] = r.Verdict
	}

	want := map[string]string{
		"/api/user/profile":  "seimbang",         // 401 anon, 200 login → guard jalan
		"/admin/desa_wisata": "anon-terbuka",     // route admin tanpa cek
		"/api/public/info":   "auth-tidak-aktif", // publik, isi sama
		"/api/account/1":     "bola-dicurigai",   // dua akun, isi beda, path ber-ID
	}
	// Placeholder tidak boleh diuji: tidak bisa dipanggil apa adanya.
	if _, ok := got["/api/account/:id"]; ok {
		t.Error("path placeholder tidak boleh masuk daftar hasil")
	}
	for p, v := range want {
		if got[p] != v {
			t.Errorf("%s = %q, mau %q", p, got[p], v)
		}
	}

	// Bukti per perspektif harus tersimpan, supaya hasil bisa diperiksa tanpa
	// menjalankan ulang.
	var res AuthzResult
	for _, r := range rep.Results {
		if r.Path == "/admin/desa_wisata" {
			res = r
		}
	}
	if res.Views["anon"].Status != 200 {
		t.Errorf("anon harus 200, dapat %d", res.Views["anon"].Status)
	}
	if res.Views["as_user_a"].Status != 200 {
		t.Errorf("as_user_a harus 200, dapat %d", res.Views["as_user_a"].Status)
	}
}

// TestAuthzRedirectTidakDiikuti — mengikuti redirect bisa mendarat di host
// lain, keluar dari scope, dan membandingkan respons antar host yang tidak
// sebanding.
func TestAuthzRedirectTidakDiikuti(t *testing.T) {
	var localext bool
	tg, _ := testTarget(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		localext = true
		fmt.Fprint(w, `{"leaked":true}`)
	}))
	t.Cleanup(other.Close)

	tg.URL = srvRedirect(t, other.URL+"/")
	rep, err := RunAuthz(context.Background(), tg.HTTPClient(), tg,
		[]Endpoint{{Path: "/admin/x", Method: "GET"}},
		AuthzOptions{Baseline: "anon", Compare: []string{"as_user_a"}})
	if err != nil {
		t.Fatal(err)
	}
	if localext {
		t.Error("redirect ke host lain tidak boleh diikuti")
	}
	if rep.Results[0].Views["anon"].Status != 302 {
		t.Errorf("status = %d, mau 302 — status redirect harus tetap tercatat", rep.Results[0].Views["anon"].Status)
	}
}

func srvRedirect(t *testing.T, to string) string {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}))
	t.Cleanup(s.Close)
	return s.URL
}

// TestConfigMultiTargetDiparse — file config harus bisa dibaca dan ditolak
// kalau tidak lengkap.
func TestConfigMultiTargetDiparse(t *testing.T) {
	cfg, err := ParseConfig(`
defaults:
  delay: 500ms
  conc: 2
  authz-skip:
    - /health
    - /static

targets:
  - name: parama-stag
    url: https://staging.kantor.id
    authz: true
    tokens:
      anon: ""
      as_user_a: "Bearer a"
      as_user_b: "Bearer b"

  - name: billing
    url: https://billing.kantor.id
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("target = %d, mau 2", len(cfg.Targets))
	}
	if cfg.Defaults.Delay != "500ms" || cfg.Defaults.Conc != 2 {
		t.Errorf("defaults = %+v", cfg.Defaults)
	}
	if len(cfg.Defaults.AuthzSkip) != 2 || cfg.Defaults.AuthzSkip[0] != "/health" {
		t.Errorf("authz-skip = %v", cfg.Defaults.AuthzSkip)
	}
	if !cfg.HasAuthz() {
		t.Error("HasAuthz harus true")
	}
	if n := len(cfg.Targets[0].TokenNames()); n != 3 {
		t.Errorf("TokenNames = %d, mau 3 (anon, a, b)", n)
	}

	// Nama perspektif harus urut dan deterministik.
	names := cfg.Targets[0].TokenNames()
	if names[0] != "anon" {
		t.Errorf("perspektif pertama = %q, mau anon", names[0])
	}
}

// TestConfigDitolakKalauTidakBisaMembuktikan — konfigurasi yang tidak bisa
// menghasilkan kesimpulan harus ditolak saat load.
func TestConfigDitolakKalauTidakBisaBProve(t *testing.T) {
	bad := []string{
		"",                        // kosong
		"targets: []\n",           // tanpa target
		"targets:\n  - name: a\n", // tanpa url
		"targets:\n  - name: a\n    url: https://x\n    authz: true\n", // authz tanpa token
		"targets:\n  - name: a\n      url: https://x\n",                // indentasi meleset
	}
	for i, src := range bad {
		if _, err := ParseConfig(src); err == nil {
			t.Errorf("kasus %d harus ditolak: %q", i, src)
		}
	}
}

// TestAuthzTidakMenulisDiLuarOutput — file laporan harus 0600 karena bisa
// memuat detail endpoint.
func TestAuthzTidakMenulisDiLuarOutput(t *testing.T) {
	dir := t.TempDir()
	tg, _ := testTarget(t)
	rep, err := RunAuthz(context.Background(), tg.HTTPClient(), tg,
		[]Endpoint{{Path: "/admin/desa_wisata", Method: "GET"}},
		AuthzOptions{Baseline: "anon", Compare: []string{"as_user_a"}})
	if err != nil {
		t.Fatal(err)
	}
	report := Report{Target: tg.URL, Stats: map[string]int{}, Endpoints: []Endpoint{}, Authz: &rep}
	style := DetectStyle(nil)
	jsonPath := filepath.Join(dir, "x.json")
	textPath := filepath.Join(dir, "x.txt")
	if err := SaveReport(jsonPath, textPath, report, style, nil, Coverage{}, false, []AuthzReport{rep}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{jsonPath, textPath} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, mau 600", p, perm)
		}
	}
	body, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "\"authz\"") {
		t.Error("JSON harus memuat bagian authz")
	}
	// Token tidak boleh bocor ke file mana pun.
	for _, p := range []string{jsonPath, textPath} {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "token-a") {
			t.Errorf("%s membocorkan token", p)
		}
	}
}

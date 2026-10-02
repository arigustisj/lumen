package lumen

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authzTarget membuat target yang menunjuk ke server uji.
func authzTarget(t *testing.T, h http.Handler) (Target, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
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

func runAuthz(t *testing.T, target Target, eps []Endpoint) AuthzReport {
	t.Helper()
	// Probe shell dimatikan di sini supaya test bisa menghitung request dengan
	// tepat. Ada test terpisah yang khusus menguji deteksi shell.
	rep, err := RunAuthz(context.Background(), target.HTTPClient(), target,
		eps, AuthzOptions{Baseline: "anon", Compare: []string{"as_user_a", "as_user_b"}, NoShellProbe: true})
	if err != nil {
		t.Fatalf("RunAuthz: %v", err)
	}
	return rep
}

func verdictOf(rep AuthzReport, path string) string {
	for _, r := range rep.Results {
		if r.Path == path {
			return r.Verdict
		}
	}
	return "<tidak ada hasil>"
}

// TestAuthzMenangkapAnonMembukaEndpointSensitif — kasus paling penting:
// route admin yang sama-sama tidak dicek, sehingga anonim masuk.
func TestAuthzMenangkapAnonMembukaEndpointSensitif(t *testing.T) {
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[1,2,3]}`)
	}))
	rep := runAuthz(t, target, []Endpoint{{Path: "/admin/desa_wisata", Method: "GET"}})

	if got := verdictOf(rep, "/admin/desa_wisata"); got != "anon-terbuka" {
		t.Fatalf("verdict = %q, mau anon-terbuka", got)
	}
	f := FindingFromAuthz(rep.Results[0])
	if f == nil {
		t.Fatal("harus menghasilkan Finding")
	}
	if f.Severity != SevHigh {
		t.Errorf("severity = %q, mau high", f.Severity)
	}
	if !strings.Contains(f.Where, "/admin/desa_wisata") {
		t.Errorf("Where harus menyebut path, dapat %q", f.Where)
	}
	// Where harus menyimpan bukti per perspektif, supaya orang bisa
	// memeriksa sendiri tanpa menjalankan ulang.
	if !strings.Contains(f.Where, "anon=200") {
		t.Errorf("Where harus mencatat status anonim, dapat %q", f.Where)
	}
	if !strings.Contains(f.Detail, "tanpa autentikasi") && !strings.Contains(f.Detail, "tanpa login") {
		t.Errorf("Detail harus menjelaskan penyebab, dapat %q", f.Detail)
	}
}

// TestAuthzMenangkapGuardTidakAktif — endpoint publik yang mengembalikan
// data apa adanya. Ini dilaporkan, tapi sebagai "low", karena memang bisa
// saja itu by design.
func TestAuthzMenangkapGuardTidakAktif(t *testing.T) {
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	rep := runAuthz(t, target, []Endpoint{{Path: "/api/public/info", Method: "GET"}})

	if got := verdictOf(rep, "/api/public/info"); got != "auth-tidak-aktif" {
		t.Fatalf("verdict = %q, mau auth-tidak-aktif", got)
	}
	if f := FindingFromAuthz(rep.Results[0]); f.Severity != SevLow {
		t.Errorf("severity = %q — endpoint publik bisa jadi by design, jangan di-high", f.Severity)
	}
}

// TestAuthzMenangkapBolaDicurigai — dua akun sah, isi berbeda, path berobjek.
func TestAuthzMenangkapBolaDicurigai(t *testing.T) {
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Authorization") {
		case "Bearer token-a":
			fmt.Fprint(w, `{"owner":"a","saldo":100}`)
		case "Bearer token-b":
			fmt.Fprint(w, `{"owner":"b","saldo":900}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	// Path IDbetulan, bukan placeholder: ":id" dilewati karena tidak bisa
	// dipanggil apa adanya.
	rep := runAuthz(t, target, []Endpoint{{Path: "/api/account/1", Method: "GET"}})

	if got := verdictOf(rep, "/api/account/1"); got != "bola-dicurigai" {
		t.Fatalf("verdict = %q, mau bola-dicurigai", got)
	}
	f := FindingFromAuthz(rep.Results[0])
	if f.Severity != SevMedium {
		t.Errorf("severity = %q, mau medium", f.Severity)
	}
	// Detail harus hati-hati: beda isi belum tentu kebocoran.
	if !strings.Contains(strings.ToLower(f.Detail), "belum jelas") {
		t.Errorf("Detail harus menyatakan ini belum pasti, dapat %q", f.Detail)
	}
}

// TestAuthzSeimbangKalauResponsBerbedaDanBerstatus — jalur sehat tidak
// boleh menghasilkan temuan.
func TestAuthzSeimbangKalauResponsBerbedaDanBerstatus(t *testing.T) {
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	rep := runAuthz(t, target, []Endpoint{{Path: "/api/user/profile", Method: "GET"}})

	if got := verdictOf(rep, "/api/user/profile"); got != "seimbang" {
		t.Fatalf("verdict = %q, mau seimbang", got)
	}
	if f := FindingFromAuthz(rep.Results[0]); f != nil {
		t.Errorf("tidak seharusnya ada Finding, dapat %+v", f)
	}
}

// TestAuthzNormalisasiFieldVolatil — dua respons identik secara isi tapi
// berbeda karena token CSRF dan timestamp harus dianggap sama. Tanpa ini,
// setiap endpoint akan dilaporkan "berbeda" dan alat ini jadi tidak berguna.
func TestAuthzNormalisasiFieldVolatil(t *testing.T) {
	var n int
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		fmt.Fprintf(w, `{"csrf_token":"abcdef%d","timestamp":100%d,"data":"sama"}`, n, n)
	}))
	// Path non-sensitif supaya vonis yang diuji adalah "guard tidak aktif",
	// bukan "anon-terbuka" yang lebih dulu Volcanic.
	rep := runAuthz(t, target, []Endpoint{{Path: "/api/info", Method: "GET"}})

	v := rep.Results[0].Views
	if v["as_user_a"].Hash != v["as_user_b"].Hash {
		t.Errorf("hash berbeda padahal hanya field volatil yang beda:\n  a=%s\n  b=%s",
			v["as_user_a"].Hash, v["as_user_b"].Hash)
	}
	if got := verdictOf(rep, "/api/info"); got != "auth-tidak-aktif" {
		t.Errorf("verdict = %q — setelah normalisasi seharusnya baru dianggap identik", got)
	}
}

// TestAuthzHanyaGET — endpoint write tidak boleh dipanggil. Ini yang menjaga
// alat ini tidak merusak data saat dijalankan.
func TestAuthzHanyaGET(t *testing.T) {
	var called []string
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = append(called, r.Method+" "+r.URL.Path)
	}))
	runAuthz(t, target, []Endpoint{
		{Path: "/api/a", Method: "GET"},
		{Path: "/api/b", Method: "POST"},
		{Path: "/api/c", Method: "PATCH"},
		{Path: "/api/d", Method: "DELETE"},
		{Path: "/api/e", Method: "PUT"},
	})
	// Setiap endpoint dipanggil sekali per perspektif (anon + 2 akun), dan
	// hanya untuk endpoint GET. Probe halaman root dimatikan supaya tidak
	// menambah hitungan — ia bukan bagian dari endpoint yang diuji.
	for _, c := range called {
		if c != "GET /api/a" {
			t.Errorf("endpoint non-GET dipanggil: %s", c)
		}
	}
	if len(called) != 3 {
		t.Errorf("dipanggil %d kali, mau 3 (satu per perspektif): %v", len(called), called)
	}
}

// TestAuthzMelewatiPathBerPlaceholder — path dengan "${e}" tidak bisa
// dipanggil apa adanya; mengujinya hanya menghasilkan noise.
func TestAuthzMelewatiPathBerPlaceholder(t *testing.T) {
	var called int
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
	}))
	rep := runAuthz(t, target, []Endpoint{
		{Path: "/admin/x/${e}/status", Method: "PATCH"},
		{Path: "/api/real", Method: "GET"},
	})
	if rep.Tested != 1 {
		t.Errorf("Tested = %d, mau 1", rep.Tested)
	}
	if called != 3 {
		t.Errorf("server dipanggil %d kali, mau 3 (satu per perspektif)", called)
	}
}

// TestAuthzTokenTidakBocorKeLaporan — nilai token tidak boleh muncul di
// Finding mana pun. Laporan sering dikirim ke orang lain.
func TestAuthzTokenTidakBocorKeLaporan(t *testing.T) {
	target, _ := authzTarget(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"x":1}`)
	}))
	rep := runAuthz(t, target, []Endpoint{{Path: "/admin/secret", Method: "GET"}})
	f := FindingFromAuthz(rep.Results[0])
	if f == nil {
		t.Fatal("harus ada Finding")
	}
	if strings.Contains(f.Where, "token-a") || strings.Contains(f.Detail, "token-a") {
		t.Errorf("token bocor ke Where/Detail: %+v", f)
	}
}

// TestAuthzHeaderUntukPerspektifAnonHarusKosong — "anon" berarti tanpa
// header. Kalau ini salah, seluruh hasil perbandingan jadi tidak berarti.
func TestAuthzHeaderUntukPerspektifAnonHarusKosong(t *testing.T) {
	tg := Target{Tokens: Tokens{"anon": "", "as_user_a": "Bearer x"}}
	if h := tg.HeaderFor("anon"); h != nil {
		t.Errorf("anon harus tanpa header, dapat %v", h)
	}
	if h := tg.HeaderFor("as_user_a"); h["Authorization"] != "Bearer x" {
		t.Errorf("token polos harus jadi header Bearer, dapat %v", h)
	}
	// Header lengkap harus dipakai apa adanya.
	tg2 := Target{Tokens: Tokens{"x": "X-Api-Key: abc"}}
	if h := tg2.HeaderFor("x"); h["X-Api-Key"] != "abc" {
		t.Errorf("header lengkap harus dipakai apa adanya, dapat %v", h)
	}
	// Token yang sudah berprefiks Bearer tidak boleh jadi Bearer Bearer.
	tg3 := Target{Tokens: Tokens{"x": "Bearer y"}}
	if h := tg3.HeaderFor("x"); h["Authorization"] != "Bearer y" {
		t.Errorf("token Bearer tidak boleh digandakan, dapat %q", h["Authorization"])
	}
}

// TestAuthzConfigButuhDuaPerspektif — konfigurasi yang tidak bisa
// menghasilkan kesimpulan harus ditolak saat load, bukan diam-diam jalan.
//
// Anon-tunggal BOLEH: tanpa login,Retrieve 200 dari endpoint sensitif sudah
// membuktikan eksposur, dan itu tidak butuh kredensial. Yang tetap ditolak
// adalah konfigurasi tanpa perspektif sama sekali.
func TestAuthzConfigButuhDuaPerspektif(t *testing.T) {
	if _, err := ParseConfig("targets:\n  - name: a\n    url: https://x.test\n    authz: true\n    tokens:\n      anon: \"\"\n"); err != nil {
		t.Fatalf("anon-tunggal harus boleh: %v", err)
	}
	if _, err := ParseConfig("targets:\n  - name: a\n    url: https://x.test\n    authz: true\n    tokens:\n      - broken\n"); err == nil {
		t.Fatal("authz tanpa perspektif yang bisa dipakai harus ditolak")
	}
	if _, err := ParseConfig("targets:\n  - name: a\n    url: https://x.test\n"); err != nil {
		t.Fatalf("config tanpa authz harus boleh: %v", err)
	}
	_ = AuthzConfig{}
	if err := (AuthzConfig{Compare: nil}).Validate(); err == nil {
		t.Fatal("AuthzConfig tanpa compare harus ditolak")
	}
	if err := (AuthzConfig{Compare: []string{"a"}}).Validate(); err != nil {
		t.Errorf("compare tunggal harus boleh: %v", err)
	}
	if err := (AuthzConfig{Compare: []string{"a", "a"}}).Validate(); err == nil {
		t.Fatal("compare duplikat harus ditolak")
	}
}

package lumen

import (
	"strings"
	"testing"
)

// TestAmbilPathDariBundle adalah inti nilai alat ini. Rute API sebuah SPA
// tidak ada di HTML — hanya string literal di dalam bundle. Kalau regex ini
// gagal, seluruh laporan jadi tidak berguna: yang tersisa hanya halaman login.
func TestAmbilPathDariBundle(t *testing.T) {
	// Cuplikan bundle React hasil minifikasi — bentuknya sama dengan yang
	// keluar dari webpack/vite.
	bundle := `
fetch("/api/users/me").then(r=>r.json());
const c=axios.create({baseURL:"/api/v2"});
axios.post("/api/orders/checkout",{items:[]});
axios({method:"DELETE",url:"/api/admin/users/42"});
fetch("/graphql",{method:"POST"});
fetch("/api/v1/products?q=shoes");
axios({method:"PUT",url:"/api/admin/config"});
const assets="/static/logo.svg";
`

	res := AnalyzeJS("app.js", bundle)

	got := map[string]string{}
	for _, e := range res.Endpoints {
		got[e.Path] = e.Method
	}

	want := map[string]string{
		"/api/users/me":            "GET",
		"/api/orders/checkout":     "POST",
		"/api/admin/users/42":      "DELETE",
		"/graphql":                 "POST",
		"/api/v1/products?q=shoes": "GET",
	}
	for path, method := range want {
		gotMethod, ok := got[path]
		if !ok {
			t.Errorf("path %q tidak ditemukan di bundle; hasilnya: %v", path, keys(got))
			continue
		}
		if gotMethod != method {
			t.Errorf("path %q: metode=%q, mau %q", path, gotMethod, method)
		}
	}

	// Bentuk axios({method, url}) — paling umum di kode yang rapi, dan
	// bentuk yang TIDAK akan tertangkap kalau hanyalooking for fetch("...").
	if got["/api/admin/config"] != "PUT" {
		t.Errorf("axios object-literal tidak terdeteksi: %v", got)
	}

	// Aset statis bukan endpoint.
	if _, bad := got["/static/logo.svg"]; bad {
		t.Error("/static/logo.svg salah dianggap endpoint")
	}
}

// TestTidakAdaEndpointKembar — setiap path harus muncul SATU kali.
//
// Tanpa ini, reAPIPath dan call-site pass sama-sama menulis hasil dan setiap
// endpoint dobel: sekali "?" sekali method asli. Laporan jadi setengah noise.
func TestTidakAdaEndpointKembar(t *testing.T) {
	bundle := `
fetch("/api/users/me");
axios.post("/api/orders",{});
axios({method:"DELETE",url:"/api/admin/x"});
fetch("/api/orders",{method:"GET"});
`
	res := AnalyzeJS("app.js", bundle)
	seen := map[string]int{}
	for _, e := range res.Endpoints {
		seen[e.Path]++
	}
	for p, n := range seen {
		if n > 1 {
			t.Errorf("path %q muncul %d kali, harus 1", p, n)
		}
	}
}

func TestTandaiAdminDanParameter(t *testing.T) {
	res := AnalyzeJS("app.js", `
axios.get("/api/admin/stats");
fetch("/api/users/"+id+"/detail");
`)
	var admin, param bool
	for _, e := range res.Endpoints {
		for _, f := range e.Flags {
			if f == "path-berisi-admin" {
				admin = true
			}
			if f == "path-berisi-parameter" {
				param = true
			}
		}
	}
	if !admin {
		t.Error("path /api/admin/... harus ditandai path-berisi-admin")
	}
	if !param {
		t.Error("path dengan {id} harus ditandai path-berisi-parameter")
	}
}

// TestTangkapKredensialTeranam — pola paling nyata di SPA: API key yang
// ditulis di source lalu jadi bagian dari file publik. Frontend tidak punya
// cara menyembunyikan apa pun yang sampai ke browser.
func TestTangkapKredensialTeranam(t *testing.T) {
	bundle := `
const cfg={apiKey:"AKIAIOSFODNN7EXAMPLE12345"};
const s2={client_secret:"xY7bQ2mNvKp4Ls9WdR1tZ6"};
fetch("https://x/",{headers:{"X-Api-Key":"abcdef1234567890zz"}});
`
	res := AnalyzeJS("app.js", bundle)
	if len(res.Secrets) == 0 {
		t.Fatal("tidak ada kredensial tertangkap dari bundle yang jelas memuat credential")
	}
	for _, s := range res.Secrets {
		if len(s.Sample) == 0 {
			t.Errorf("secret %s tidak punya sample", s.Kind)
		}
		// Sample harus tersamar — laporan bisa dibaca orang lain.
		if strings.Contains(s.Sample, "AKIAIOSFODNN7EXAMPLE12345") {
			t.Error("nilai kredensial tidak disamarkan di sample")
		}
	}
}

func TestDeteksiFramework(t *testing.T) {
	cases := []struct {
		body string
		want string
	}{
		{`<script id="__NEXT_DATA__" type="application/json">{}</script>`, "Next.js"},
		{`<div id="root"></div>`, "SPA (id=root) — kemungkinan React"},
		{`<div data-v-a1b2c3d4></div>`, "Vue"},
	}
	for _, c := range cases {
		found := false
		for _, f := range DetectFramework(c.body) {
			if f == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("DetectFramework(%q) tidak memuat %q, dapat %v", c.body, c.want, DetectFramework(c.body))
		}
	}
}

// TestCanonicalMencegahCrawlerBerulang — tanpa ini satu aplikasi dengan
// /index.html, /index.php, dan / akan di-crawl tiga kali dan report-nya
// contains duplikat.
func TestCanonicalMencegahCrawlerBerulang(t *testing.T) {
	cases := [][2]string{
		{"https://a.test/index.html", "https://a.test/index"},
		{"https://a.test/index.php", "https://a.test/index"},
		{"https://a.test/dir/", "https://a.test/dir"},
		{"https://a.test/x#frag", "https://a.test/x"},
	}
	for _, c := range cases {
		if got := Canonical(c[0]); got != c[1] {
			t.Errorf("Canonical(%q) = %q, mau %q", c[0], got, c[1])
		}
	}
}

func TestAbsResolveTolakJavascriptURL(t *testing.T) {
	base := "https://a.test/page"
	for _, bad := range []string{"javascript:void(0)", "#top", "mailto:x@y.z", "data:text/html,x", ""} {
		if _, ok := AbsResolve(base, bad); ok {
			t.Errorf("AbsResolve(%q) seharusnya ditolak", bad)
		}
	}
	if got, ok := AbsResolve(base, "/api/x"); !ok || got != "https://a.test/api/x" {
		t.Errorf("AbsResolve path relatif = %q (ok=%v)", got, ok)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

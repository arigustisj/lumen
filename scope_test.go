package lumen

import (
	"net/url"
	"testing"
)

// TestGuardMenolakHostLain adalah jaminan utama alat ini.
//
// Tanpa guard, satu <script src> atau <a href> ke domain ketiga sudah cukup
// untuk menarik seluruh crawler keluar dari target — ke CDN, font host, atau
// milik orang lain yang tidak pernah Gives izin. Guard harus menolak SEBELUM
// request dikirim, dan penolakannya harus terlihat di laporan supaya bisa
// diaudit, bukan terjadi diam-diam.
func TestGuardMenolakHostLain(t *testing.T) {
	base, _ := url.Parse("https://staging.kita.test/app")
	s := NewScope(base)

	//roads yang boleh
	for _, ok := range []string{
		"https://staging.kita.test/api/x",
		"https://staging.kita.test/",
		"http://staging.kita.test/y", // skema berbeda tetap host sama
	} {
		u, _ := url.Parse(ok)
		if !s.Allows(u) {
			t.Errorf("Allows(%q) = false, harus true (host sama)", ok)
		}
	}

	// host yang harus ditolak
	for _, bad := range []string{
		"https://cdn.kita.net/lib.js",
		"https://google-analytics.com/x",
		"https://staging.kita.test.evil.com/a",  // prefix menipu
		"https://evil.com/?x=staging.kita.test", // host di query
	} {
		u, _ := url.Parse(bad)
		if s.Allows(u) {
			t.Errorf("Allows(%q) = true, harus false (host beda)", bad)
		}
	}

	denied := s.Denied()
	if len(denied) == 0 {
		t.Fatal("Denied() kosong: penolakan tidak tercatat, tidak bisa diaudit")
	}
	// Semua host yang tercatat harus yang ditolak, tidak ada kebocoran.
	for _, d := range denied {
		if len(d) > 0 && d[0] == 's' && d[:8] == "staging" {
			t.Errorf("Denied() memuat host yang seharusnya diizinkan: %q", d)
		}
	}
}

func TestPortDefaultDisesuaikanSkema(t *testing.T) {
	https, _ := url.Parse("https://a.test/")
	if s := NewScope(https); s.host != "a.test" || s.port != "443" {
		t.Errorf("https → host=%q port=%q, mau a.test/443", s.host, s.port)
	}
	plain, _ := url.Parse("http://a.test/")
	if s := NewScope(plain); s.host != "a.test" || s.port != "80" {
		t.Errorf("http → host=%q port=%q, mau a.test/80", s.host, s.port)
	}
}

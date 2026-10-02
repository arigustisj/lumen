package lumen

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sesi berbasis cookie.
//
// -
// Mengapa ini perlu
// -
//
// Mayoritas aplikasi web tidak memakai header token. Mereka memberi cookie
// sesi HttpOnly lalu membacanya dari request. Frontend-nya memanggil
// fetch(..., {credentials:"include"}) dan tidak pernah menyentuh header
// Authorization sama sekali.
//
// Tester yang hanya bisa mengirim header akan mendapat hasil yang buruk
// pada aplikasi semacam ini: setiap perspektif mendapat respons yang
// persis sama — bukan karena otorisasi kuat, tetapi karena tidak ada yang
// pernah masuk. Kesimpulannya "auth tidak aktif" akan salah, dan salah di
// sini berbahaya: ia melaporkan aplikasi yang belum diuji sebagai aplikasi
// yang sudah terbukti tidak aman.
//
// -
// Yang ditangani di sini
// -
//
//   - Cookie sesi pada konfigurasi dipasang ke jar, bukan dikirim sebagai
//     header statis.
//   - Set-Cookie dari respons disimpan, sehingga rotasi sesi (server yang
//     memperpanjang cookie tiap request) tetap berjalan.
//   - Cookie CSRF/XSRF Bridges otomatis ke header yang sesuai, karena
//     aplikasi yang memakai cookie hampir selalu memerlukannya dan
//     tanpanya setiap request POST akan ditolak 403 — yang akan disalahartikan
//     sebagai "terjaga" padahal sebenarnya tidak ada yang diuji.

const maxCookieWait = 2 * time.Second

// Clients menyimpan satu http.Client per perspektif.
//
// Dipisah karena dua alasan yang keduanya penting:
//
//	Sesi tidak boleh bocor antar perspektif. Kalau alice dan bob memakai jar
//	yang sama, request keduabob bisa membawa cookie milik alice dan seluruh
//	perbandingan jadi tidak berarti.
//
//	Cookie harus bertahan antar request. Header statis tidak; sesi yang
//	dirotasi server akan fell off setelah satu request.
type Clients struct {
	base *http.Client
	tgt  Target
	mu   sync.Mutex
	per  map[string]*http.Client
}

// NewClients membangun Clients untuk sekumpulan perspektif.
//
// base dipakai kembali untuk perspektif yang tidak butuh kredensial, agar
// -anon- tidak berlaku dan tidak menambah connection overhead.
func NewClients(t Target, perspectives []string, base *http.Client) *Clients {
	c := &Clients{base: base, tgt: t, per: map[string]*http.Client{}}
	for _, p := range perspectives {
		c.clientFor(p)
	}
	return c
}

func (c *Clients) clientFor(pers string) *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cl, ok := c.per[pers]; ok {
		return cl
	}

	u, err := url.Parse(c.tgt.URL)
	if err != nil {
		u = &url.URL{}
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		jar = nil
	}

	cl := *c.base // salin, jangan berbagi
	if jar != nil {
		cl.Jar = jar
		// Seed cookie dari konfigurasi. Nilai "Cookie: a=b; c=d" diubah
		// menjadi cookie sungguhan agar bisa diperbarui server.
		if raw := cookieSeed(c.tgt.HeaderFor(pers)); raw != "" && jar != nil {
			if u.Scheme != "" && u.Host != "" {
				jar.SetCookies(u, parseCookieHeader(raw))
			}
		}
	}
	c.per[pers] = &cl
	return &cl
}

// For mengembalikan client untuk sebuah perspektif.
func (c *Clients) For(pers string) *http.Client {
	if c == nil {
		return nil
	}
	if v := strings.TrimSpace(c.tgt.Tokens[pers]); v == "" {
		// Perspektif tanpa kredensial memakai client dasar supaya tidak
		// ada biaya yang tidak perlu.
		return c.base
	}
	return c.clientFor(pers)
}

// HasSession melaporkan apakah perspektif punya kredensial.
func (c *Clients) HasSession(pers string) bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.tgt.Tokens[pers]) != ""
}

// WithCSRF menyalin cookie CSRF dari jar ke header.
//
// Tanpa ini, aplikasi berbasis cookie akan menolak setiap request dengan
// 403 karena header CSRF tidak ada. Itu 403 akan dibaca sebagai "guard
// bekerja" — kesimpulan yang benar secara teknis dan menyesatkan secara
// substansi: yang ditolak bukan akses tanpa izin, melainkan request yang
// tidak berbentuk.
func WithCSRF(client *http.Client, req *http.Request) {
	if req == nil || client == nil || req.URL == nil {
		return
	}
	if req.Header.Get("X-CSRF-Token") != "" || req.Header.Get("X-XSRF-TOKEN") != "" {
		return
	}
	js := client.Jar
	if js == nil {
		return
	}
	// Pencocokan dilakukan dengan "mengandung", bukan daftar nama persis.
	//
	// Nama cookie CSRF berbeda antara setiap framework: XSRF-TOKEN (Rails,
	// Laravel), csrftoken (Django), csrfToken (NextAuth), _csrf, dan
	// seterusnya. Daftar nama persis akan selalu menyisakan satu framework
	// yang gagal dan menghasilkan 403 — dan 403 itu akan dibaca sebagai
	// "guard bekerja", yaitu kesimpulan yang benar secara harfiah dan salah
	// secara substansi.
	for _, ck := range js.Cookies(req.URL) {
		n := strings.ToLower(ck.Name)
		if ck.Value != "" && (strings.Contains(n, "csrf") || strings.Contains(n, "xsrf")) {
			req.Header.Set("X-CSRF-Token", ck.Value)
			req.Header.Set("X-XSRF-TOKEN", ck.Value)
			return
		}
	}
}

// cookieSeed mengambil nilai header Cookie dari HeaderFor.
func cookieSeed(h map[string]string) string {
	for k, v := range h {
		if strings.EqualFold(k, "Cookie") {
			return v
		}
	}
	return ""
}

// parseCookieHeader mengubah "a=b; c=d" menjadi []*http.Cookie.
//
// Cookie tanpa nilai (flag seperti "Secure" sendirian) diabaikan: tidak ada
// nilai untuk dikirim danDamaged mengabaikannya lebih aman daripada menebak.
func parseCookieHeader(raw string) []*http.Cookie {
	var out []*http.Cookie
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)
		if name == "" || val == "" {
			continue
		}
		// Buang tanda kutip bila ada.
		val = strings.Trim(val, `"`)
		out = append(out, &http.Cookie{Name: name, Value: val, Path: "/"})
	}
	return out
}

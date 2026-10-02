package lumen

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ── authz differential ─────────────────────────────────────────────────────
//
// Static mapping bisa memberitahu "ini endpoint sensitif". Yang tidak bisa ia
// lakukan adalah menjawab pertanyaan yang sebenarnya penting: apakah endpoint
// itu sudah dijaga.
//
// Pemeriksaan ini menjawabnya dengan cara yang tidak merusak: kirim GET yang
// identik kecuali header otorisasi, lalu bandingkan respons. Kalau dua akses
// yang seharusnya berbeda perlakuan menghasilkan respons yang sama,
// authorization di sana tidak melakukan apa pun.
//
// Yang tidak dilakukan di sini: menulis data, mengunggah berkas, mencoba
// muatan, menebak credential, atau mengubah state. Hanya GET.

// AuthzResult adalah hasil untuk satu endpoint.
type AuthzResult struct {
	Path      string
	Views     map[string]View
	Verdict   string
	Why       string
	Sensitive bool
}

// View adalah satu respons untuk satu perspektif.
type View struct {
	Perspective string
	Status      int
	Length      int
	Hash        string
	Error       string
	Redirect    string
	ElapsedMS   int64
}

// sameBody membandingkan dua tampilan.
//
// Length dan hash dihitung dari body yang sudah dinormalisasi. Tanpa itu,
// field yang memang berubah tiap request (token CSRF, timestamp, request id)
// membuat dua respons identik terlihat berbeda, dan setiap endpoint akan
// dilaporkan "berbeda" — pemeriksaan ini jadi tidak berguna.
func (a View) sameBody(b View) bool {
	if a.Status != b.Status {
		return false
	}
	if a.Status < 200 || a.Status >= 300 {
		// Di luar 2xx, body hampir selalu halaman error generik. Yang penting
		// statusnya sama, bukan isi halaman login-nya.
		return true
	}
	if a.Error != "" || b.Error != "" {
		return a.Error == b.Error
	}
	return a.Hash == b.Hash && a.Length == b.Length
}

// AuthzReport adalah hasil untuk satu target.
type AuthzReport struct {
	Target   string
	Baseline string
	Compared []string
	Results  []AuthzResult
	Given    int
	Tested   int
	Skipped  int
}

// AuthzOptions mengatur pemeriksaan.
type AuthzOptions struct {
	Baseline  string
	Compare   []string
	DelayMS   int
	SkipPaths []string
	OnlyPaths []string
}

// RunAuthz menguji endpoint milik satu target.
//
// Endpoint yang diuji diambil dari hasil ekstraksi surface, supaya daftar ini
// sama persis dengan yang dipakai laporan. Dua daftar terpisah akan
// menghasilkan laporan yang saling menycontradictory.
func RunAuthz(ctx context.Context, client *http.Client, target Target, endpoints []Endpoint, opts AuthzOptions) (AuthzReport, error) {
	rep := AuthzReport{Target: target.Name, Baseline: opts.Baseline, Compared: opts.Compare}
	if rep.Baseline == "" {
		rep.Baseline = "anon"
	}
	rep.Given = len(endpoints)

	// Hanya GET dan HEAD. Endpoint yang metode utamanya write diskip: menguji
	// otorisasi dengan cara memanggilnya berarti menjalankan write yang tidak
	// perlu terjadi hanya untuk membuktikan sesuatu.
	var paths []string
	seen := map[string]bool{}
	for _, e := range endpoints {
		m := strings.ToUpper(e.Method)
		if m != "" && m != "GET" && m != "HEAD" {
			rep.Skipped++
			continue
		}
		if seen[e.Path] || !authzPathAllowed(e.Path, opts) {
			rep.Skipped++
			continue
		}
		seen[e.Path] = true
		paths = append(paths, e.Path)
	}
	sort.Strings(paths)

	order := append([]string{rep.Baseline}, opts.Compare...)
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		res := AuthzResult{Path: p, Views: map[string]View{}, Sensitive: isSensitivePath(p)}
		for _, pers := range order {
			res.Views[pers] = fetchView(ctx, client, target, p, pers)
			if opts.DelayMS > 0 {
				select {
				case <-ctx.Done():
					return rep, ctx.Err()
				case <-time.After(time.Duration(opts.DelayMS) * time.Millisecond):
				}
			}
		}
		rep.Tested++
		judge(&res, rep.Baseline)
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

// judge menetapkan vonis untuk satu endpoint.
//
// Empat bentuk kesimpulan yang bisa diambil dari perbandingan GET:
//
//	anon-terbuka     anonim mendapat 2xx pada endpoint sensitif
//	auth-tidak-aktif anonim dan terotorisasi identik → guard tidak mengubah apa pun
//	bola-dicurigai   dua akun sah mendapat 200 dengan isi berbeda pada path berobjek
//	lainnya         ada perbedaan, jadi ada sesuatu yang bekerja
//
// Yang tidak dilakukan: menyimpulkan "aman" dari respons yang sama. Respons
// identik bisa berarti datanya memang publik, dan itu tidak bisa dibedakan
// dari kelalaian tanpa knowing endpoint-nya.
func judge(r *AuthzResult, baseline string) {
	base, ok := r.Views[baseline]
	if !ok {
		r.Verdict = "tidak-ada-baseline"
		return
	}
	anon := r.Views["anon"]

	// 1. Anonim masuk ke endpoint sensitif.
	if anon.Status >= 200 && anon.Status < 300 && r.Sensitive {
		r.Verdict = "anon-terbuka"
		r.Why = fmt.Sprintf("tanpa login sudah dapat %d (%d byte) dari endpoint sensitif", anon.Status, anon.Length)
		return
	}

	// 2. Otorisasi tidak mengubah apa pun.
	for _, pers := range sortedViewKeys(r.Views) {
		if pers == baseline {
			continue
		}
		v := r.Views[pers]
		// Hanya berlaku pada respons sukses. Dua perspektif yang sama-sama
		// dapat 404 atau 500 bukan berarti otorisasi tidak bekerja — itu
		// berarti request-nya salah, dan oversaw itu akan-reported
		// sebagai temuan palsu.
		if v.sameBody(base) && base.Status >= 200 && base.Status < 300 {
			r.Verdict = "auth-tidak-aktif"
			r.Why = fmt.Sprintf("%s dan %s memberi respons identik (%d) — guard otorisasi tidak mengubah apa pun",
				pers, baseline, base.Status)
			return
		}
	}

	// 3. Dua akun sah, isi berbeda, pada endpoint berparameter objek.
	if r.Sensitive && hasObjectParam(r.Path) {
		var ok200 []string
		for _, pers := range sortedViewKeys(r.Views) {
			if pers == "anon" {
				continue
			}
			if v := r.Views[pers]; v.Status >= 200 && v.Status < 300 {
				ok200 = append(ok200, pers)
			}
		}
		if len(ok200) >= 2 && distinctBodies(r.Views, ok200) {
			r.Verdict = "bola-dicurigai"
			r.Why = fmt.Sprintf("%s dan %s sama-sama dapat 200 dengan isi berbeda — kepemilikan objek belum diperiksa",
				ok200[0], ok200[1])
			return
		}
	}

	r.Verdict = "seimbang"
}

func distinctBodies(views map[string]View, keys []string) bool {
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			a, b := views[keys[i]], views[keys[j]]
			if a.Hash != b.Hash || a.Length != b.Length {
				return true
			}
		}
	}
	return false
}

// FindingFromAuthz mengubah vonis menjadi Finding.
//
// Detail dirangkai dari template per kelas supaya setiap baris punya
// penyebab, cara verifikasi, dan arah perbaikan — bukan cuma nama aturan.
func FindingFromAuthz(r AuthzResult) *Finding {
	if r.Verdict == "" || r.Verdict == "seimbang" || r.Verdict == "tidak-ada-baseline" {
		return nil
	}
	sev := SevLow
	switch r.Verdict {
	case "anon-terbuka":
		sev = SevHigh
	case "bola-dicurigai":
		sev = SevMedium
	}

	views := make([]string, 0, len(r.Views))
	for _, k := range sortedViewKeys(r.Views) {
		v := r.Views[k]
		if v.Error != "" {
			views = append(views, fmt.Sprintf("%s=%s", k, v.Error))
			continue
		}
		views = append(views, fmt.Sprintf("%s=%d/%dB", k, v.Status, v.Length))
	}

	var cause, how string
	switch r.Verdict {
	case "anon-terbuka":
		cause = "Endpoint sensitif dapat diakses tanpa autentikasi."
		how = "Uji manual: panggil tanpa header Authorization dan bandingkan dengan yang memakai akun valid. Kalau tetap 200, route ini tidak diprotect."
	case "auth-tidak-aktif":
		cause = "Respons identik dengan dan tanpa login, jadi pemeriksaan otorisasi di route ini tidak mengubah hasil. Bisa jadi memang endpoint publik — perlu dipastikan."
		how = "Uji manual: panggil tanpa login dan bandingkan isi. Kalau isinya sama persis, cek apakah middleware benar-benar terpasang di route ini."
	case "bola-dicurigai":
		cause = "Dua akun berbeda mendapat 200 dengan isi berbeda pada endpoint berparameter objek. Belum jelas itu kebocoran data milik orang lain atau memang respons per pengguna."
		how = "Uji manual: pakai akun B untuk meminta ID milik akun A. Kalau B dapat data A, itu BOLA (API1). Server harus cek kepemilikan, bukan hanya 'sudah login'."
	}

	return &Finding{
		Kind:     "authz-" + r.Verdict,
		Severity: sev,
		Where:    "GET " + r.Path + "  [" + strings.Join(views, " | ") + "]",
		Detail:   cause + " " + r.Why + ". " + how,
	}
}

// fetchView mengirim satu GET dan merangkum responsnya.
//
// Body dibaca dengan batas. Endpoint yang mengembalikan arsip besar akan
// memakai banyak memori kalau tidak dibatasi, dan untuk perbandingan
// otorisasi beberapa ratus kilobyte pertama sudah lebih dari cukup.
func fetchView(ctx context.Context, client *http.Client, target Target, path, pers string) View {
	v := View{Perspective: pers}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL+path, nil)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	for k, hv := range target.HeaderFor(pers) {
		req.Header.Set(k, hv)
	}
	// Minta respons apa adanya, tanpa kompresi: yang dibandingkan adalah byte.
	req.Header.Set("Accept-Encoding", "identity")

	started := time.Now()
	resp, err := client.Do(req)
	v.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		v.Error = err.Error()
		return v
	}
	defer resp.Body.Close()

	v.Status = resp.StatusCode
	if loc := resp.Header.Get("Location"); loc != "" {
		v.Redirect = loc
	}

	const limit = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil && len(body) == 0 {
		v.Error = err.Error()
		return v
	}
	if len(body) > limit {
		body = body[:limit]
	}
	norm := normalizeBody(body)
	v.Length = len(norm)
	sum := sha256.Sum256(norm)
	v.Hash = hex.EncodeToString(sum[:8])
	return v
}

// volatileKeys adalah nama field yang memang ought berubah tiap request.
var volatileKeys = []string{
	"csrf", "token", "nonce", "request_id", "requestid", "trace",
	"timestamp", "expires", "jti", "etag", "session_id", "sessionid",
}

// normalizeBody membuang bagian yang berubah-ubah antar-request.
func normalizeBody(b []byte) []byte {
	s := string(b)
	if i := strings.IndexByte(s, '{'); i > 0 && looksLikeHTML(s[:i]) {
		s = s[i:] // buang halaman login sebelum JSON-nya
	}
	for _, k := range volatileKeys {
		s = scrubField(s, k)
	}
	return []byte(s)
}

func looksLikeHTML(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(l, "<!doctype") || strings.HasPrefix(l, "<html")
}

// scrubField mengganti nilai field bernama k, baik string maupun angka.
//
// Nilai non-string harus ikut diganti. Kalau hanya string yang digantikan,
// field seperti "timestamp":1700000000 tetap berbeda tiap request dan
// setiap endpoint akan terbaca "berbeda" — persis yang mau dihindari.
func scrubField(s, k string) string {
	for i := 0; i < 64; i++ {
		idx := strings.Index(strings.ToLower(s), `"`+k)
		if idx < 0 {
			return s
		}
		colon := strings.IndexByte(s[idx:], ':')
		if colon < 0 {
			return s
		}
		colon += idx
		p := colon + 1
		for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
			p++
		}
		if p >= len(s) {
			return s
		}
		var end int
		if s[p] == '"' {
			end = p + 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				return s
			}
			s = s[:p] + `"__X__"` + s[end+1:]
			continue
		}
		if s[p] == '{' || s[p] == '[' {
			// Objek atau array: tidak consumido, hanya tandai agar loop
			// tidak berputar pada field yang sama. Isinya dibiarkan apa
			// adanya karena tidak ada cara aman menormalkan isinya.
			s = s[:colon+1] + ` "__X__"` + s[colon+1:]
			continue
		}
		// Angka atau literal: konsumsi sampai penanda berikutnya.
		end = p
		for end < len(s) && s[end] != ',' && s[end] != '}' && s[end] != ']' {
			end++
		}
		if end == p {
			end = p + 1
		}
		s = s[:p] + `0` + s[end:]
	}
	return s
}

// authzPathAllowed menyaring endpoint yang tidak layak diuji authz.
//
// Placeholder dilewati: "${e}" dan ":id" tidak bisa dipanggil apa adanya.
// Mengujinya hanya menghasilkan respons error yang sama untuk semua
// perspektif, dan itu akan terbaca sebagai temuan palsu.
func authzPathAllowed(path string, o AuthzOptions) bool {
	if strings.Contains(path, "${") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "{") {
			return false
		}
	}
	if len(o.OnlyPaths) > 0 {
		for _, p := range o.OnlyPaths {
			if strings.Contains(path, p) {
				return true
			}
		}
		return false
	}
	for _, p := range o.SkipPaths {
		if strings.Contains(path, p) {
			return false
		}
	}
	return true
}

// hasObjectParam menandai path yang isinya sebuah objek.
//
// Bentuk yang paling sering muncul di aplikasi nyata bukan placeholder
// seperti ":id" — melainkan angka atau UUID di path:
// /api/account/1, /api/order/9f2c-..., /api/user/42/detail. Placeholder
// sendiri dilewati oleh authzPathAllowed karena tidak bisa dipanggil apa
// adanya, jadi di sini yang dicari justru ID yang bisa di-enumerate.
func hasObjectParam(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if isNumericID(seg) || isUUIDish(seg) {
			return true
		}
	}
	return strings.Contains(path, "id=") || strings.Contains(path, "_id")
}

// isNumericID mengenali segmen yang seluruhnya angka.
func isNumericID(seg string) bool {
	if len(seg) > 18 { // ID database realistis tidak sepanjang ini
		return false
	}
	for _, r := range seg {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(seg) > 0
}

// isUUIDish mengenali segmen berpola hex panjang dengan tanda hubung —
// bentuk UUID dan object id yang umum dipakai.
func isUUIDish(seg string) bool {
	core := strings.ReplaceAll(seg, "-", "")
	if len(core) < 16 || len(core) > 40 {
		return false
	}
	for _, r := range core {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// sensitiveKeywords menandai endpoint yang layak ditinjau dengan prioritas
// lebih tinggi. Diambil dari permukaan API umum.
var sensitiveKeywords = []string{
	"/admin", "/internal", "/actuator", "/manage", "/management",
	"/user", "/users", "/account", "/profile", "/customer", "/client",
	"/order", "/orders", "/payment", "/invoice", "/transaction", "/wallet",
	"/salary", "/payroll", "/employee", "/patient", "/member",
	"/setting", "/config", "/token", "/session", "/key", "/secret",
}

func isSensitivePath(path string) bool {
	l := strings.ToLower(path)
	for _, k := range sensitiveKeywords {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func sortedViewKeys(m map[string]View) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Package extract mengurai HTML dan JavaScript bundle.
//
// Ini inti nilai tool ini. Untuk SPA (React/Next/Vue), rute API tidak ada di
// HTML — HTML cuma punya satu div kosong dan tag <script>. Crawler biasa akan
// selalu melaporkan "halaman login saja" dan berhenti di sana. Rute sebenarnya
// ada sebagai string literal di dalam bundle, dan di situlah yang perlu dibaca.
package extract

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"lumen/internal/model"
)

// --- HTML ------------------------------------------------------------------

var (
	reTitle  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reScript = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	reLink   = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"']+)["']`)
	reFormIn = regexp.MustCompile(`(?is)<input[^>]+name=["']([^"']+)["']`)
	reFormAc = regexp.MustCompile(`(?is)<form[^>]+action=["']([^"']+)["']`)
)

func Title(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	t := strings.Join(strings.Fields(m[1]), " ")
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

func Scripts(body string) []string { return dedup(reMatches(reScript, body)) }
func Links(body string) []string   { return dedup(reMatches(reLink, body)) }
func FormActions(body string) []string {
	return dedup(reMatches(reFormAc, body))
}

func FormFields(body string) []string { return dedup(reMatches(reFormIn, body)) }

// --- Framework detection --------------------------------------------------

var (
	reNextData = regexp.MustCompile(`__NEXT_DATA__`)
	reNuxt     = regexp.MustCompile(`(?i)__NUXT__`)
	reVueAttr  = regexp.MustCompile(`(?i)data-v-[0-9a-f]{8}`)
	reSvelte   = regexp.MustCompile(`(?i)svelte-[0-9a-z]{6}`)
)

// DetectFramework menandai framework dari marker di HTML. Hasilnya informatif
// saja — sering salah untuk app yang self-hosted, jadi dipakai sebagai petunjuk
// arah investigasi, bukan bukti.
func DetectFramework(body string) []string {
	var out []string
	if reNextData.MatchString(body) {
		out = append(out, "Next.js")
	}
	if reNuxt.MatchString(body) {
		out = append(out, "Nuxt")
	}
	if reVueAttr.MatchString(body) {
		out = append(out, "Vue")
	}
	if reSvelte.MatchString(body) {
		out = append(out, "Svelte")
	}
	if reNextData.MatchString(body) {
		return out
	}
	if strings.Contains(body, `id="root"`) || strings.Contains(body, `id='root'`) {
		out = append(out, "SPA (id=root) — kemungkinan React")
	}
	return out
}

// --- JavaScript bundle ----------------------------------------------------

// reAPIPath menangkap string yang tampak seperti path API.
//
// Sengaja longgar: false positive itu murah (bakal di-review manusia),
// sementara false negative berarti endpoint yang tidak pernah ditemukan sama
// sekali. Untuk alat pemetaan, lebih baik lebih.
var reAPIPath = regexp.MustCompile(
	`["'\x60](/(?:api|v\d|graphql|rest|auth|admin|user|users|payment|checkout|` +
		`order|orders|product|products|webhook|webhooks|internal|config|settings|` +
		`upload|download|export|import|search|profile)[a-zA-Z0-9_\-/{}$.:]{0,140})["'\x60]`)

// reFetchCall menangkap argumen pertama fetch()/axios dengan window kecil
// di depannya, supaya metode HTTP bisa ditebak dari konteks pemanggil.
// reFetchCall menangkap pemanggilan dengan argumen path berupa string.
//
// Pola DASARNYA adalah "nama[..].metode(" — bukan daftar nama library
// tertentu. Aplikasi nyata hampir selalu memakai instance sendiri
// (const api=axios.create(); api.post("/api/x")) dan pola hardcode
// axios/fetch akan melewatkan semuanya. Yang penting bentuk pemanggilannya,
// bukan nama pustakanya.
var reFetchCall = regexp.MustCompile(
	`(?is)[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){0,2}\s*\(\s*["'\x60](/[^"'\x60]{1,200})["'\x60]`)

// reObjectURL menangkap bentuk axios({ method:"POST", url:"/api/x" }) dan
// fetch(new Request("/api/x")). Tanpa ini, endpoint yang ditulis dalam object
// literal — bentuk paling umum di kode yang rapi — tidak pernah terlihat.
var reObjectURL = regexp.MustCompile(
	`(?is)url\s*:\s*["'\x60]([^"'\x60]{1,200})["'\x60]`)

var (
	reHTTPVerb = regexp.MustCompile(`(?i)\b(method|type)\s*:\s*["'](POST|PUT|PATCH|DELETE)["']`)
	reTech     = regexp.MustCompile(`(?i)\b(react|next|vue|nuxt|angular|svelte|gorm|prisma|sequelize|knex|tailwind|bootstrap|jquery)\b`)
)

// reEmbeddedKey mencari credential yang ikut ter-commit ke bundle.
//
// Ini temuan paling nyata di SPA: API key, token, dan password yang ditulis
// langsung di kode lalu jadi bagian dari file publik. Karena frontend tidak
// punya cara menyembunyikan apa pun yang sampai ke browser, setiap match di
// sini harus dianggap terekspos sampai dirotasi.
// reEmbeddedKey punya DUA kelompok: yang pertama adalah penanda tipe
// (prefix bekannt atau nama field), yang kedua nilai rahasianya.
//
// valeur captured sebagai label harus jadi bisa dibaca dan aman dicetak —
// kalau yang diambil adalah nilai kredensial itu sendiri, laporan jadi
// menyalin kredensial utuh ke file dan ke terminal.
var reEmbeddedKey = regexp.MustCompile(
	`(?i)((?:sk_live|pk_live|sk_test|AIza|ghp_|xox[baprs]-|AKIA)[A-Za-z0-9_\-]{8,}|` +
		`(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|password|passwd)` +
		`["'\s]{0,4}[:=]\s*["'\x60])` +
		`(["'\x60]?)([A-Za-z0-9_\-\/\+=]{16,})`)

// JSResult adalah hasil analisis satu bundle.
type JSResult struct {
	Endpoints []model.Endpoint
	Tech      []string
	Secrets   []Secret
	Bytes     int
}

type Secret struct {
	Kind   string
	Sample string
}

// AnalyzeJS membaca satu bundle dan menarik endpoint, tech stack, dan
// credential yang tertanam.
func AnalyzeJS(src, body string) JSResult {
	res := JSResult{Bytes: len(body)}

	// Dikelompokkan per path. Pass pertama (reAPIPath) hanya tahu path;
	// pass kedua (call site) tahu method. Kalau keduanya ditulis langsung ke
	// slice, setiap endpoint muncul dua kali: sekali dengan "?" dan sekali
	// dengan method aslinya — dan sheet hasilnya dobel.
	type entry struct {
		method string
		flags  []string
		done   bool
	}
	found := map[string]*entry{}
	var order []string

	get := func(p string) *entry {
		if e, ok := found[p]; ok {
			return e
		}
		e := &entry{method: "?"}
		found[p] = e
		order = append(order, p)
		return e
	}

	// Pass 1: path yang terlihat sebagai string literal saja.
	for _, mt := range reAPIPath.FindAllStringSubmatch(body, -1) {
		get(strings.TrimSpace(mt[1]))
	}

	// Pass 2: call site — punya posisi, jadi method bisa ditentukan.
	for _, re := range []*regexp.Regexp{reFetchCall, reObjectURL} {
		for _, loc := range re.FindAllStringSubmatchIndex(body, -1) {
			ref := body[loc[2]:loc[3]]
			if !strings.HasPrefix(ref, "/") {
				continue // URL absolut/eksternal: bukan milik target
			}
			e := get(ref)
			// Kalau path ini sudah punya method dari call site sebelumnya,
			// lewati: reFetchCall dan reObjectURL bisa sama-sama cocok pada
			// statement yang sama, dan memprosesnya dua kali menghasilkan
			// flag kembar.
			if e.method != "?" && e.done {
				continue
			}
			method, flags := guessMethod(body, loc[2])
			if e.method == "?" || method != "?" {
				e.method = method
			}
			e.flags = dedupFlags(append(e.flags, flags...))
			e.done = true
		}
	}

	sort.Strings(order)
	for _, p := range order {
		e := found[p]
		// Dedup terakhir di titik emisi. Baris di dalam loop sudah
		// menormalkan, tapi jalur lain (gabungan hasil probe di cmd/)
		// bisa menambah flag yang sama lagi, dan flag kembar bikin
		// output terlihat jauh lebih banyak tanpa menambah informasi.
		res.Endpoints = append(res.Endpoints, model.Endpoint{
			Method: e.method, Path: p, Origin: model.OriginJS,
			Source: src, Flags: dedupFlags(e.flags),
		})
	}

	tseen := map[string]bool{}
	for _, t := range reTech.FindAllString(body, -1) {
		l := strings.ToLower(t)
		if !tseen[l] {
			tseen[l] = true
			res.Tech = append(res.Tech, t)
		}
	}
	sort.Strings(res.Tech)

	for _, mt := range reEmbeddedKey.FindAllStringSubmatch(body, -1) {
		// mt[1] = penanda tipe (prefix atau nama field) — aman dicetak.
		// mt[3] = nilai rahasianya — hanya untuk disamarkan.
		kind := classifySecret(mt[1])
		res.Secrets = append(res.Secrets, Secret{Kind: kind, Sample: mask(mt[3])})
	}

	return res
}

// guessMethod menebak metode HTTP dari statement yang memuat call site pada pos.
//
// Kalau tidak ada petunjuk, "?" — lebih jujur daripada mengarang GET,
// karena endpoint bisa saja hanya menerima POST, dan mengarang GET membuat
// orang salah prioritas saat menguji.
func guessMethod(body string, pos int) (string, []string) {
	// Batas per-statement, bukan jendela karakter tetap.
	//
	// Bundle minified menaruh banyak request dalam satu baris tanpa spasi:
	//   axios.post("/api/a",{});axios({method:"DELETE",url:"/api/b"})
	// Jendela karakter tetap akan melewati batas itu dan mengambil method milik
	// request sebelah — metode tertukar diam-diam. Memperluas ke statement
	// terdekat (delimiter ; { }) mengisolasi setiap request.
	lo, hi := statementBounds(body, pos)
	seg := body[lo:hi]

	// Path yang dirujuk, untuk mengukur jarak dan menandai parameter.
	ref, refAt, viaObject := "", pos, false
	if loc := reFetchCall.FindStringSubmatchIndex(seg); loc != nil {
		ref, refAt = seg[loc[2]:loc[3]], loc[2]
	} else if loc := reObjectURL.FindStringSubmatchIndex(seg); loc != nil {
		ref, refAt, viaObject = seg[loc[2]:loc[3]], loc[2], true
	}

	// Verb eksplisit menang: pola axios({method:"POST", url:...}).
	method := ""
	if m := reHTTPVerb.FindStringSubmatchIndex(seg); m != nil {
		method = strings.ToUpper(seg[m[4]:m[5]])
	}

	if method == "" {
		// Tanpa method eksplisit, ambil verb yang posisinya paling dekat
		// dengan path yang dirujuk. Memilih kemunculan pertama bisa
		// mengambil verb milik request lain di statement yang sama.
		lower := strings.ToLower(seg)
		best, bestDist := "", len(seg)+1
		for _, v := range []string{"delete", "patch", "post", "put", "get"} {
			for off := 0; ; {
				i := strings.Index(lower[off:], v)
				if i < 0 {
					break
				}
				i += off
				off = i + len(v)
				d := i - refAt
				if d < 0 {
					d = -d
				}
				if d < bestDist {
					best, bestDist = v, d
				}
			}
		}
		method = strings.ToUpper(best)
	}

	var flags []string
	ll := strings.ToLower(ref)
	switch {
	case strings.Contains(ll, "admin"):
		flags = append(flags, "path-berisi-admin")
	case strings.Contains(ll, "internal"):
		flags = append(flags, "path-berisi-internal")
	}

	// Path param dicek dari seluruh statement, bukan hanya string path-nya,
	// karena bentuk paling umum adalah konkatenasi: fetch("/api/u/"+id).
	// Hanya tandai kalau pola parameter muncul DEKAT dengan path yang
	// dirujuk. Memeriksa seluruh statement membuat hampir semua endpoint
	// mendapat flag ini — di bundle minified, statement sering
	// memuat beberapa request dan salah satu punya template literal, sehingga
	// endpoint yang statis ikut ditandai. Flag yang selalu menyala tidak
	// membawa informasi.
	near := seg
	if d := 120; len(near) > d {
		start := refAt - d/2
		if start < 0 {
			start = 0
		}
		end := refAt + len(ref) + d/2
		if end > len(near) {
			end = len(near)
		}
		near = near[start:end]
	}
	if strings.ContainsAny(ref, "{}$:") ||
		strings.Contains(near, "${") ||
		reConcatNear.MatchString(near) {
		flags = append(flags, "path-berisi-parameter")
	}

	if method == "" {
		// fetch("/api/x") dan axios("/api/x") sama-sama default ke GET.
		// Bentuk object literal tanpa method tidak bisa diasumsikan —
		// jadi di sana tetap "?" dan ditandai perlu dibaca manual.
		if viaObject {
			method = "?"
			flags = append(flags, "metode-tidak-terbaca")
		} else {
			method = "GET"
		}
	}
	return method, dedupFlags(flags)
}

// reConcatNear menangkap penggabungan string dengan variabel di sekitar path
// yang dirujuk, mis. "/"+id+"". Versi lama memeriksa seluruh statement dan
// yang dirujuk, mis. "/"+id+"". Versi lama memeriksa seluruh statement dan
var reConcatNear = regexp.MustCompile(`\+\s*[A-Za-z_$][\w$]*\s*\+`)

// statementBounds memperluas pos ke delimiter statement terdekat.
func statementBounds(body string, pos int) (int, int) {
	lo := 0
	for i := pos - 1; i >= 0; i-- {
		// Hanya ';' dan newline yang memisahkan statement. Kurung kurawal
		// TIDAK: object literal adalah bagian dari pemanggilan, jadi
		// axios({method:"POST",url:"/api/x"}) akan terpotong tepat sebelum
		// method-nya terbaca.
		if c := body[i]; c == ';' || c == '\n' {
			lo = i + 1
			break
		}
		if pos-i > 200 { // jangan telusuri terlalu jauh pada bundle besar
			lo = i
			break
		}
	}
	hi := len(body)
	for i := pos; i < len(body); i++ {
		if c := body[i]; c == ';' || c == '\n' {
			hi = i
			break
		}
		if i-pos > 200 {
			hi = i
			break
		}
	}
	return lo, hi
}

func dedupFlags(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, f := range in {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// classifySecret mengubah penanda mentah menjadi label yang bisa dibaca.
func classifySecret(marker string) string {
	l := strings.ToLower(marker)
	switch {
	case strings.HasPrefix(l, "sk_live"), strings.HasPrefix(l, "sk_test"):
		return "stripe-key"
	case strings.HasPrefix(l, "pk_live"):
		return "stripe-publishable"
	case strings.HasPrefix(l, "aiza"):
		return "google-api-key"
	case strings.HasPrefix(l, "ghp_"):
		return "github-token"
	case strings.HasPrefix(l, "xox"):
		return "slack-token"
	case strings.HasPrefix(l, "akia"):
		return "aws-access-key"
	case strings.Contains(l, "client_secret"):
		return "client-secret"
	case strings.Contains(l, "access_token"):
		return "access-token"
	case strings.Contains(l, "api_key"), strings.Contains(l, "apikey"):
		return "api-key"
	case strings.Contains(l, "passw"):
		return "password"
	case strings.Contains(l, "secret"):
		return "secret"
	}
	return "kredensial"
}

// mask menyembunyikan sebagian nilai supaya secret bisa dilaporkan tanpa
// ikut menyalin kredensial utuh ke file output.
func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}

// --- URL helpers ----------------------------------------------------------

// AbsResolve mengubah referensi relatif jadi absolut terhadap base.
func AbsResolve(base, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") ||
		strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") ||
		strings.HasPrefix(ref, "data:") {
		return "", false
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	abs := b.ResolveReference(r)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false
	}
	abs.Fragment = ""
	return abs.String(), true
}

// Canonical menormalkan URL supaya halaman yang sama tidak di-crawl berkali-kali
// lewat path berbeda (/index.html, /index.php, /?a=1).
func Canonical(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	for _, ext := range []string{".html", ".php", ".asp", ".aspx", ".jsp"} {
		if strings.HasSuffix(strings.ToLower(u.Path), ext) {
			u.Path = strings.TrimSuffix(u.Path, u.Path[len(u.Path)-len(ext):])
			u.RawQuery = ""
			break
		}
	}
	if p := strings.TrimSuffix(u.Path, "/"); p == "" {
		u.Path = "/"
	} else {
		u.Path = p
	}
	return u.String()
}

func QueryKeys(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	q := u.Query()
	if len(q) == 0 {
		return nil
	}
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func reMatches(re *regexp.Regexp, s string) []string {
	ms := re.FindAllStringSubmatch(s, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return out
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

package lumen

import (
	"sort"
	"strings"
)

// Taksonomi temuan.
//
// Rujukan: OWASP API Security Top 10 (2023) dan OWASP Web Top 10 (2021),
// masing-masing dipetakan ke CWE. CWE dipakai karena itu identifier yang
// dipahami tool Static Application Security Testing dan code scanning —
// label OWASP saja tidak bisa_search dan tidak bisa di-machine-process.
//
// PENTING soal status: semua yang dihasilkan classify() adalah KANDIDAT,
// bukan temuan terbukti. Klasifikasi ini berdasarkan sinyal statis (pola
// path, flag, header) tanpa melihat logika otorisasi server. Menyebutnya
// "vulnerability" tanpa bukti akan membuat orang meng-Rh Vergangenheit hal
// yang belum diperiksa; lebih jujur menyebut kandidat dan menyebut persyarat
// apa yang harus diuji untuk memastikan/menolak.
//
// Diadaptasi dari pola yang dipakai Strix (usestrix/strix), yang secara
// eksplisitQBecks track "honest per-category coverage" — kategori yang tidak
// diuji dilaporkan sebagai tidak diuji, bukan lolos.

type Category struct {
	ID    string   // "API1:2023"
	Title string   // "Broken Object Level Authorization"
	CWE   []string // "CWE-639", "CWE-284"
	URL   string
}

// webTop10 adalah OWASP Top 10 2021.
var webTop10 = []Category{
	{"A01:2021", "Broken Access Control", []string{"CWE-284"}, "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
	{"A02:2021", "Cryptographic Failures", []string{"CWE-327", "CWE-319"}, "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
	{"A03:2021", "Injection", []string{"CWE-89", "CWE-79", "CWE-78"}, "https://owasp.org/Top10/A03_2021-Injection/"},
	{"A04:2021", "Insecure Design", []string{"CWE-501"}, "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
	{"A05:2021", "Security Misconfiguration", []string{"CWE-16", "CWE-611"}, "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
	{"A06:2021", "Vulnerable and Outdated Components", []string{"CWE-1104"}, "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
	{"A07:2021", "Identification and Authentication Failures", []string{"CWE-287", "CWE-306"}, "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
	{"A08:2021", "Software and Data Integrity Failures", []string{"CWE-502", "CWE-494"}, "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
	{"A09:2021", "Security Logging and Monitoring Failures", []string{"CWE-778"}, "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"},
	{"A10:2021", "Server-Side Request Forgery", []string{"CWE-918"}, "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
}

// apiTop10 adalah OWASP API Security Top 10 2023 — yang paling relevan untuk
// hasil lumen, karena sebagian besar temuan datang dari path yang ditemukan di
// bundle, yaitu permukaan API.
var apiTop10 = []Category{
	{"API1:2023", "Broken Object Level Authorization", []string{"CWE-639", "CWE-284"}, "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
	{"API2:2023", "Broken Authentication", []string{"CWE-287", "CWE-306"}, "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"},
	{"API3:2023", "Broken Object Property Level Authorization", []string{"CWE-639", "CWE-915"}, "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"},
	{"API4:2023", "Unrestricted Resource Consumption", []string{"CWE-770", "CWE-400"}, "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"},
	{"API5:2023", "Broken Function Level Authorization", []string{"CWE-862", "CWE-863"}, "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"},
	{"API6:2023", "Unrestricted Access to Sensitive Business Flows", []string{"CWE-841"}, "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"},
	{"API7:2023", "Server Side Request Forgery", []string{"CWE-918"}, "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"},
	{"API8:2023", "Security Misconfiguration", []string{"CWE-16"}, "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"},
	{"API9:2023", "Improper Inventory Management", []string{"CWE-200", "CWE-1053"}, "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"},
	{"API10:2023", "Unsafe Consumption of APIs", []string{"CWE-918", "CWE-20"}, "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"},
}

var allCategories = append(append([]Category{}, webTop10...), apiTop10...)

func categoryByID(id string) (Category, bool) {
	for _, c := range allCategories {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// Candidate adalah satu kandidat kerentanan beserta dasar penilaiannya.
//
// Verify berisi syarat yang harus diuji manusia untuk memastikan ATAU
// menyangkal. Tanpa field ini, daftar kandidat jadi daftar tebakan.
type Candidate struct {
	ID         string   `json:"id"`
	Category   string   `json:"category"` // ID kategori OWASP
	Title      string   `json:"title"`
	CWE        []string `json:"cwe,omitempty"`
	Confidence string   `json:"confidence"` // high | medium | low
	Where      string   `json:"where"`
	Signal     string   `json:"signal"` // bukti statis yang memunculkan ini
	Verify     string   `json:"verify"` // langkah konfirmasi manual
	Remediate  string   `json:"remediate"`
}

// Classify mengubah endpoint + temuan menjadi daftar kandidat kerentanan.
//
// Hanya sinyal statis yang dipakai: pola path, flag dari probe, dan header
// yang hilang. Lumen tidak pernah melakukan login, jadi tidak bisa membuktikan
// sebuah endpoint terotorisasi atau tidak. Karena itu hasilnya disebut
// KANDIDAT, bukan temuan — dan setiap kandidat membawa langkah verifikasi
// supaya orang bisa mengonfirmasi ATAU menyangkal, bukan asal percaya.
func Classify(eps []Endpoint, findings []Finding) []Candidate {
	var out []Candidate
	seen := map[string]bool{}

	add := func(c Candidate) {
		key := c.Category + "|" + c.Where
		if seen[key] {
			return
		}
		seen[key] = true
		if cat, ok := categoryByID(c.Category); ok {
			if c.Title == "" {
				c.Title = cat.Title
			}
			if len(c.CWE) == 0 {
				c.CWE = cat.CWE
			}
		}
		out = append(out, c)
	}

	for _, e := range eps {
		if e.Origin != OriginJS {
			continue
		}
		p := e.Path
		lower := strings.ToLower(p)
		hasParam := strings.ContainsAny(p, "{}$:") || hasFlag(e, "path-berisi-parameter")
		isAdmin := strings.Contains(lower, "/admin") || strings.Contains(lower, "/internal")
		isAuth := strings.Contains(lower, "/auth") || strings.Contains(lower, "/login") ||
			strings.Contains(lower, "/logout")
		authed := hasFlag(e, "terproteksi-auth")
		open := hasFlag(e, "AKSES-TANPA-AUTH")

		// BOLA (API1) — pola paling fruitful di API modern: path dengan
		// parameter yang menunjuk objek milik user. Kalau otorisasi
		// per-pemilik tidak ditegakkan di server, user mana pun bisa membaca
		// data user lain hanya dengan menukar ID.
		if hasParam && !isAuth {
			conf := "medium"
			signal := "path dengan parameter objek: " + p
			if open {
				conf = "high"
				signal += "; merespons 2xx tanpa auth pada OPTIONS"
			}
			if isAdmin {
				conf = "high"
				signal += "; pada endpoint admin"
			}
			add(Candidate{
				Category:   "API1:2023",
				Confidence: conf,
				Where:      p,
				Signal:     signal,
				Verify: "Log in sebagai user A, ambil satu ID objek milik user B, lalu " +
					"panggil endpoint ini dengan ID itu. Bila data B dikembalikan, itu BOLA. " +
					"Pisahkan juga dua kasus: 'tidak punya akses' (403) dan 'tidak ada' (404) — " +
					"mengembalikan 403 justru membocorkan keberadaan objek.",
				Remediate: "Terapkan otorisasi per-objek di server pada setiap request, " +
					"bukan hanya menyembunyikan tombol di UI. Pastikan query filter " +
					"juga ikut membatasi, bukan hanya path.",
			})
		}

		// Broken Function Level Authorization (API5) — endpoint admin yang
		// bisa diakses tanpa login adalah temuan paling serius di daftar ini.
		if isAdmin {
			conf := "medium"
			signal := "path admin"
			switch {
			case open:
				conf = "high"
				signal += "; OPTIONS 2xx tanpa auth"
			case authed:
				conf = "low"
				signal += "; memakai proteksi auth"
			}
			add(Candidate{
				Category:   "API5:2023",
				Confidence: conf,
				Where:      p,
				Signal:     signal,
				Verify: "Panggil tanpa cookie/session, lalu dengan session user biasa " +
					"(bukan admin). Endpoint harus menolak keduanya dengan 401/403. " +
					"Catatan: OPTIONS 2xx tidak membuktikan GET juga terbuka.",
				Remediate: "Terapkan pemeriksaan role di setiap handler admin, terutama " +
					"untuk method yang mengubah state (POST/PUT/PATCH/DELETE).",
			})
		}

		// CORS longgar — respons yang bisa dibaca lintas origin.
		if hasCORSFlag(e) {
			add(Candidate{
				Category:   "A05:2021",
				Confidence: "high",
				Where:      p,
				Signal:     "Access-Control-Allow-Origin longgar pada " + p,
				Verify: "Kirim OPTIONS dengan Origin: https://evil.example dan lihat " +
					"apakah ACAO memantulkan origin itu. Kalau ya, respons bisa " +
					"dibaca cross-origin dari browser mana pun.",
				Remediate: "Whitelist origin secara eksplisit. Jangan pernah memakai " +
					"wildcard bersamaan dengan Access-Control-Allow-Credentials.",
			})
		}

		// Method penulisan pada path statis — perlu dicek CSRF.
		if isWriteMethod(e.Method) && !hasParam {
			add(Candidate{
				Category:   "API5:2023",
				Confidence: "low",
				Where:      p,
				Signal:     "method penulisan (" + e.Method + ") pada path statis",
				Verify: "Panggil tanpa auth. Periksa juga apakah endpoint menerima " +
					"request dari form lintas situs — kalau iya, itu CSRF.",
				Remediate: "Wajibkan session dan periksa Origin/Referer untuk operasi tulis.",
			})
		}
	}

	// ── temuan konfigurasi ────────────────────────────────────────────────
	for _, f := range findings {
		switch f.Kind {
		case "header":
			switch {
			case strings.Contains(f.Detail, "Content-Security-Policy"):
				add(Candidate{
					Category: "A05:2021", Confidence: "medium", Where: f.Where,
					Signal: "Content-Security-Policy tidak ada",
					Verify: "Cek dulu apakah ada CSP di header lain atau sebagai meta tag " +
						"sebelum menyimpulkan tidak ada sama sekali.",
					Remediate: "Terapkan CSP restrictive (default-src 'self'), dan hindari " +
						"unsafe-inline di script-src kalau memungkinkan.",
				})
			case strings.Contains(f.Detail, "Strict-Transport-Security"):
				add(Candidate{
					Category: "A02:2021", Confidence: "medium", Where: f.Where,
					Signal: "HSTS tidak ada — downgrade ke HTTP masih mungkin",
					Verify: "Pastikan situs sudah redirect HTTP ke HTTPS. HSTS tanpa " +
						"redirect hanya menambah header, tidak melindungi apa pun.",
					Remediate: "Kirim Strict-Transport-Security: max-age=31536000; includeSubDomains.",
				})
			case strings.Contains(f.Detail, "X-Frame-Options"):
				add(Candidate{
					Category: "A05:2021", Confidence: "low", Where: f.Where,
					Signal: "X-Frame-Options tidak ada",
					Verify: "Cek apakah CSP frame-ancestors sudah mengaturnya sebagai " +
						"pengganti. Tanpa salah satu, situs bisa dibungkus iframe.",
					Remediate: "Kirim X-Frame-Options: DENY, atau frame-ancestors 'none' di CSP.",
				})
			}
		case "cors":
			add(Candidate{
				Category: "A05:2021", Confidence: "high", Where: f.Where,
				Signal:    f.Detail,
				Verify:    "Uji dengan Origin mencurigakan; pastikan respons tidak memantulkan origin penyerang.",
				Remediate: "Whitelist origin. Jangan pernah wildcard + credentials.",
			})
		case "cookie":
			if strings.Contains(f.Detail, "tanpa flag Secure") {
				add(Candidate{
					Category: "A02:2021", Confidence: "medium", Where: f.Where,
					Signal: f.Detail,
					Verify: "Lihat apakah cookie ini yang jadi sandaran otorisasi. Kalau iya, " +
						"nilainya bisa direbut lewat MITM.",
					Remediate: "Tambahkan flag Secure pada cookie session dan auth.",
				})
			}
			if strings.Contains(f.Detail, "tanpa HttpOnly") {
				add(Candidate{
					Category: "A07:2021", Confidence: "low", Where: f.Where,
					Signal:    f.Detail,
					Verify:    "Cek apakah nilainya token session. Cookie tanpa HttpOnly bisa dicuri XSS.",
					Remediate: "Tambahkan HttpOnly pada cookie session.",
				})
			}
		case "secret-di-bundle":
			add(Candidate{
				Category: "A02:2021", Confidence: "high", Where: f.Where,
				Signal: f.Detail,
				Verify: "Tentukan apakah kredensial ini nyata dan masih aktif. Kalau iya, " +
					"anggap bocor sejak lama: rotasi, jangan hanya dihapus dari kode.",
				Remediate: "Pindahkan ke backend. Apa pun yang sampai ke browser dianggap " +
					"publik, apa pun niatnya. Rotasi kredensial lama, lalu simpan di " +
					"secret store sisi server.",
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if a, b := confRank(out[i].Confidence), confRank(out[j].Confidence); a != b {
			return a < b
		}
		return out[i].Where < out[j].Where
	})
	return out
}

func confRank(c string) int {
	switch c {
	case "high":
		return 0
	case "medium":
		return 1
	}
	return 2
}

func hasFlag(e Endpoint, want string) bool {
	for _, f := range e.Flags {
		if f == want {
			return true
		}
	}
	return false
}

func hasCORSFlag(e Endpoint) bool {
	for _, f := range e.Flags {
		if strings.HasPrefix(f, "cors-allow-origin") {
			return true
		}
	}
	return false
}

func isWriteMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// Coverage menyatakan apa yang benar-benar dianalisis dan apa yang tidak.
//
// Ini yang membedakan laporan yang bisa dipercaya dari laporan yang membuat
// orang salah tidur. "Tidak ada temuan" tanpa pernyataan cakupan hanya berarti
// "tidak ada yang kita lihat" — bukan "aman".
//
// Pola yang sama dipakai Strix (usestrix/strix): exit code 0 hanya mencakup
// apa yang benar-benar dianalisis, dan secara eksplisit melacak cakupan per
// kategori alih-alih melaporkan kategori yang tidak diuji sebagai "lolos".
type Coverage struct {
	Analysed  []string `json:"analysed"`
	NotTested []string `json:"not_tested"`
	Limits    []string `json:"limits"`
}

// BuildCoverage menyusun pernyataan cakupan dari statistik scan.
func BuildCoverage(r Report) Coverage {
	c := Coverage{
		Analysed: []string{
			"permukaan HTML yang terjangkau lewat link dalam scope",
			"JavaScript bundle: path API, method HTTP, tech stack",
			"pola kredensial yang tertanam di bundle",
			"header keamanan HTTP per halaman",
			"flag cookie (HttpOnly, Secure, SameSite)",
			"konfigurasi CORS pada respons yang terambil",
		},
		NotTested: []string{
			"logika otorisasi server — BOLA/BFLA butuh dua akun berbeda",
			"injection — butuh request yang benar-benar mengubah state",
			"password, reset token, dan alur autentikasi",
			"service worker, IndexedDB, WebSocket",
			"host dan subdomain lain di luar origin yang diberikan",
			"kerentanan dependency — butuh SBOM",
			"sesi setelah login — lumen tidak pernah melakukan login",
		},
		Limits: []string{
			"hanya GET dan OPTIONS; tidak ada request yang mengubah state",
			"klasifikasi OWASP adalah kandidat dari sinyal statis, bukan bukti",
			"respons 2xx pada OPTIONS tidak membuktikan GET juga terbuka",
		},
	}
	if r.Stats["bundle"] == 0 {
		c.Limits = append(c.Limits,
			"TIDAK ADA bundle yang terbaca — analisis JS dilewati seluruhnya, "+
				"jadi sebagian besar permukaan API belum terlihat sama sekali")
	}
	return c
}

// exitCode mengikuti konvensi yang dipakai Strix supaya pipeline bisa
// membedakan tiga keadaan yang sangat berbeda:
//
//	0 — tidak ada kandidat confidence tinggi
//	2 — ada kandidat high (bukan "rentan terbukti", tapi perlu dilihat)
//	3 — scan tidak bisa dipercaya: bundle tidak terbaca sama sekali
//
// Exit code 3 sengaja ada. Tanpa itu, scan yang gagal membaca target akan
// terlihat IDENTIK dengan scan yang bersih — dan itu penyebab paling umum
// pipenya berg falsely green.
func ExitCode(r Report, cands []Candidate) int {
	if r.Stats["bundle"] == 0 {
		return 3
	}
	for _, c := range cands {
		if c.Confidence == "high" {
			return 2
		}
	}
	return 0
}

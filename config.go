package lumen

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config untuk pemakaian internal: banyak target, token per target, dan
// nilai default yang tidak harus diketik ulang setiap kali.
//
// Format file YAML subset — baca ParseYAML.
type Config struct {
	Defaults Defaults
	Targets  []Target
}

// Defaults adalah nilai bawaan yang bisa dioverride per target.
type Defaults struct {
	Delay    string
	Conc     int
	Timeout  string
	Probe    bool
	MaxDepth int
	// AuthzOnly dan AuthzSkip menyaring endpoint yang diuji otorisasi.
	// Kosong = uji semua GET yang layak.
	AuthzOnly []string
	AuthzSkip []string
}

// Target adalah satu layanan yang akan dipetakan.
//
// Authz hanya menyala kalau ada minimal dua perspektif untuk dibandingkan
// (lihat AuthzConfig.Validate). Tanpa itu, "--authz" hanya menambah beban
// tanpa menghasilkan kesimpulan apa pun.
type Target struct {
	Name   string
	URL    string
	Authz  bool
	Tokens Tokens
}

// Tokens adalah kredensial per perspektif.
//
// Peta, bukan field terpisah, karena jumlah perspektif bisa lebih dari tiga
// dan setiap target punya kombinasi sendiri. Nilai adalah header siap pakai
// ("Bearer xyz"), bukan token mentah — supaya konfigurasi ini bisa ditulis
// ulang oleh orang lain tanpa harus tahu format tiap provider.
//
// File ini bisa mengandung token. Jangan di-commit; lihat example.
type Tokens map[string]string

// AuthzConfig menjelaskan cara membandingkan dua akses atas endpoint yang sama.
type AuthzConfig struct {
	// Baseline adalah perspektif yang dipakai sebagai pembanding. Default
	// "anon" adalah perspektif pembanding: mencari apa yang bocor tanpa login.
	Baseline string
	// Compare adalah daftar perspektif lain yang dibandingkan dengan baseline.
	Compare []string
	// SkipPatterns dan OnlyPatterns menyaring endpoint mana yang diuji.
	SkipPatterns []string
	OnlyPatterns []string
}

// Validate menolak konfigurasi yang tidak bisa menghasilkan kesimpulan.
//
// Ini sengaja galak. Tes authz yang tidak bisa membuktikan apa pun lebih
// berbahaya daripada tidak jalan: hasilya terlihat meyakinkanwhile empty.
func (c AuthzConfig) Validate() error {
	if c.Baseline == "" {
		c.Baseline = "anon"
	}
	if len(c.Compare) == 0 {
		return fmt.Errorf("authz: butuh minimal satu perspektif pembanding (compare)")
	}
	seen := map[string]bool{c.Baseline: true}
	for _, p := range c.Compare {
		if p == "" {
			return fmt.Errorf("authz: nama perspektif kosong di compare")
		}
		if seen[p] {
			return fmt.Errorf("authz: perspektif %q muncul dua kali", p)
		}
		seen[p] = true
	}
	return nil
}

// LoadConfig membaca file konfigurasi.
func LoadConfig(path string) (Config, error) {
	var c Config
	src, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("baca config: %w", err)
	}
	return ParseConfig(string(src))
}

// ParseConfig menafsirkan isi konfigurasi.
func ParseConfig(src string) (Config, error) {
	var c Config
	root, err := ParseYAML(src)
	if err != nil {
		return c, fmt.Errorf("config: %w", err)
	}

	if d, ok := root["defaults"]; ok && d != nil {
		m, err := AsMap(d, "defaults")
		if err != nil {
			return c, err
		}
		if c.Defaults.Delay, err = AsString(m["delay"], "defaults.delay"); err != nil {
			return c, err
		}
		if v, err := AsString(m["conc"], "defaults.conc"); err == nil && v != "" {
			if n, err := atoiSafe(v); err != nil {
				return c, fmt.Errorf("defaults.conc: %w", err)
			} else if n > 0 {
				c.Defaults.Conc = n
			}
		}
		if c.Defaults.Timeout, err = AsString(m["timeout"], "defaults.timeout"); err != nil {
			return c, err
		}
		if c.Defaults.Probe, err = AsBool(m["probe"], "defaults.probe"); err != nil {
			return c, err
		}
		if c.Defaults.AuthzOnly, err = stringList(m["authz-only"], "defaults.authz-only"); err != nil {
			return c, err
		}
		if c.Defaults.AuthzSkip, err = stringList(m["authz-skip"], "defaults.authz-skip"); err != nil {
			return c, err
		}
		if v, err := AsString(m["max-depth"], "defaults.max-depth"); err == nil && v != "" {
			if n, err := atoiSafe(v); err != nil {
				return c, fmt.Errorf("defaults.max-depth: %w", err)
			} else if n > 0 {
				c.Defaults.MaxDepth = n
			}
		}
	}

	list, err := AsList(root["targets"], "targets")
	if err != nil {
		return c, err
	}
	if len(list) == 0 {
		return c, fmt.Errorf("config: tidak ada target")
	}
	for i, tv := range list {
		path := fmt.Sprintf("targets[%d]", i)
		m, err := AsMap(tv, path)
		if err != nil {
			return c, err
		}
		var t Target
		if t.Name, err = AsString(m["name"], path+".name"); err != nil {
			return c, err
		}
		if t.Name == "" {
			t.Name = fmt.Sprintf("target-%d", i+1)
		}
		if t.URL, err = AsString(m["url"], path+".url"); err != nil {
			return c, err
		}
		if t.URL == "" {
			return c, fmt.Errorf("%s.url: wajib diisi", path)
		}
		if t.Authz, err = AsBool(m["authz"], path+".authz"); err != nil {
			return c, err
		}
		if tk, ok := m["tokens"]; ok && tk != nil {
			tm, err := AsMap(tk, path+".tokens")
			if err != nil {
				return c, err
			}
			t.Tokens = Tokens{}
			for k, v := range tm {
				sv, err := AsString(v, path+".tokens."+k)
				if err != nil {
					return c, err
				}
				// "anon" sengaja boleh kosong: nilai kosongnya justru
				// maksudnya — perspektif tanpa header otorisasi. Kalau
				// ikut disaring, perspektif yang paling penting untuk
				// mencari kebocoran justru hilang diam-diam.
				if sv != "" || k == "anon" {
					t.Tokens[k] = sv
				}
			}
		}
		if t.Authz {
			// Perspektif anonim selalu ada, walau tidak ditulis di config:
			// tanpa itu tidak ada yang bisa dibandingkan dengan akses
			// tanpa login, dan itu justru kasus yang paling sering bocor.
			if _, ok := t.Tokens["anon"]; !ok {
				if t.Tokens == nil {
					t.Tokens = Tokens{}
				}
				t.Tokens["anon"] = ""
			}
			// Satu perspektif cukup untuk membuktikan eksposur anonim, dan
			// itu tidak butuh kredensial apa pun.
			//
			// Dua akun baru dibutuhkan untuk hal yang lebih halus:
			// membedakan "ownership tidak dicek" dari "data ini memang
			// publik". Menolak konfigurasi anonim-tunggal membuat orang
			// mengira tidak ada yang bisa dicek sama sekali, padahal
			// pemeriksaan paling mendasar sudah bisa jalan tanpa login.
			if len(t.Tokens) == 0 {
				return c, fmt.Errorf("%s: authz butuh minimal perspektif anon", path)
			}
		}
		c.Targets = append(c.Targets, t)
	}
	return c, nil
}

// HasAuthz memberitahu apakah ada target yang mengaktifkan authz.
func (c Config) HasAuthz() bool {
	for _, t := range c.Targets {
		if t.Authz {
			return true
		}
	}
	return false
}

// HTTPClient mengembalikan client untuk menguji target.
//
// Timeout dibatasi karena pemeriksaan authz mengirim banyak request serial ke
// server yang mungkin lambat atau sudah down. Tanpa batas, satu endpoint yang
// tidak merespons akan menggantung seluruh scan.
func (t Target) HTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		// Redirect tidak diikutkan. Ikutinya berarti request bisa mendarat di
		// host lain — keluar dari scope — dan membandingkan respons antar host
		// yang tidak sebanding. Status redirect-nya sendiri sudah dicatat.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TokenNames mengembalikan nama perspektif yang tersedia untuk sebuah target,
// urut dan tanpa duplikat.
func (t Target) TokenNames() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range []string{"anon", "as_user_a", "as_user_b", "as_user_c"} {
		if _, ok := t.Tokens[k]; ok && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	// Sisanya tetap diambil, tapi setelah yang dikenal supaya urutan config
	// tidak mengubah urutan tampilan laporan.
	var rest []string
	for k := range t.Tokens {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sortStrings(rest)
	return append(out, rest...)
}

// HeaderFor mengembalikan header siap pakai untuk sebuah perspektif.
//
// "anon" berarti tanpa header otorisasi sama sekali — itu titik pembanding
// paling penting, karena hampir semua kebocoran otorisasi mem manifests di
// sini lebih dulu.
func (t Target) HeaderFor(perspective string) map[string]string {
	v, ok := t.Tokens[perspective]
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	// Kalau sudah berupa header lengkap ("Authorization: Bearer x"), pakai
	// apa adanya. Kalau cuma nilai token, pilih header standar.
	if strings.Contains(v, ":") {
		h := map[string]string{}
		name, val, _ := strings.Cut(v, ":")
		h[strings.TrimSpace(name)] = strings.TrimSpace(val)
		return h
	}
	switch {
	case strings.HasPrefix(strings.ToLower(v), "bearer "):
		return map[string]string{"Authorization": v}
	default:
		return map[string]string{"Authorization": "Bearer " + v}
	}
}

func atoiSafe(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("kosong")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("%q bukan angka bulat", s)
		}
		n = n*10 + int(r-'0')
		if n > 1_000_000 {
			return 0, fmt.Errorf("%q terlalu besar", s)
		}
	}
	return n, nil
}

// stringList membaca nilai list of scalars. String tunggal juga diterima
// supaya menulis satu pola tidak perlu Ribet list satu elemen.
func stringList(v any, path string) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	if sv, ok := v.(string); ok {
		if sv == "" {
			return nil, nil
		}
		return []string{sv}, nil
	}
	l, err := AsList(v, path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(l))
	for i, e := range l {
		sv, err := AsString(e, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if sv != "" {
			out = append(out, sv)
		}
	}
	return out, nil
}

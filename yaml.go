package lumen

import (
	"fmt"
	"strconv"
	"strings"
)

// Parser YAML subset.
//
// Kenapa tidak pakai library: Lumen sengaja nol dependensi eksternal, supaya
// binary-nya kecil dan bisa di-build cross-platform tanpa toolchain tambahan.
// Yang dibutuhkan hanya config yang enak dibaca manusia, jadi subset ini
// cukup: mapping, list, scalar, komentar, dan kutip opsional.
//
// Yang TIDAK didukung (dan memang tidak perlu): anchor, alias, tag, multi-
// line literal, flow collection, dan key duplikat. Kalau ada yang di luar itu,
// parser mengembalikan error jelas — bukan diam-diam menafsirkan lain.

// ParseYAML mengubah teks YAML subset menjadi map[string]any.
//
// Nilai yang dihasilkan: map[string]any, []any, string, bool, int, float64,
// atau nil. Semua key selalu string.
func ParseYAML(src string) (map[string]any, error) {
	lines, err := yamlLines(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	v, next, err := parseBlock(lines, 0, lines[0].indent)
	if err != nil {
		return nil, err
	}
	if next < len(lines) {
		return nil, fmt.Errorf("baris %d: indentasi tidak konsisten", lines[next].no)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("dokumen harus berupa mapping di baris teratas")
	}
	return m, nil
}

type yamlLine struct {
	no     int
	indent int
	text   string
}

// yamlLines membuang baris kosong dan komentar, lalu menghitung indentasi.
// Indentasi dihitung dari spasi di depan teks. Isi baris tetap disimpan
// utuh supaya kutip dan spasi di dalam nilai tidak berubah diam-diam.
func yamlLines(src string) ([]yamlLine, error) {
	var out []yamlLine
	for i, raw := range strings.Split(src, "\n") {
		no := i + 1
		// Tab di awal indentasi selalu salah: YAMLFV menolaknya, dan Tools
		// YAMLFV yang memb.allow tab akan menghasilkan indentasi yang berbeda
		// antara editor dan program. Lebih baik ditolak eksplisit.
		if i := strings.IndexByte(raw, '\t'); i >= 0 && strings.TrimSpace(raw[:i]) == "" {
			return nil, fmt.Errorf("baris %d: pakai spasi, bukan tab, untuk indentasi", no)
		}
		line := strings.TrimRight(raw, " \r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		out = append(out, yamlLine{no: no, indent: indent, text: strings.TrimSpace(line)})
	}
	return out, nil
}

// parseBlock membaca seluruh blok pada indentasi tertentu. Melewati blok
// list ("- ") dan mapping ("key:") secara terpisah karena cara keduanya
// mendeteksi akhir blok berbeda.
func parseBlock(ls []yamlLine, i, indent int) (any, int, error) {
	if i >= len(ls) {
		return nil, i, nil
	}
	if strings.HasPrefix(ls[i].text, "- ") || ls[i].text == "-" {
		return parseList(ls, i, indent)
	}
	return parseMap(ls, i, indent)
}

func parseMap(ls []yamlLine, i, indent int) (any, int, error) {
	m := map[string]any{}
	for i < len(ls) {
		l := ls[i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, i, fmt.Errorf("baris %d: indentasi meleset ke dalam tanpa kunci", l.no)
		}
		if strings.HasPrefix(l.text, "- ") {
			return nil, i, fmt.Errorf("baris %d: list di dalam mapping pada indentasi yang sama", l.no)
		}
		key, rest, ok := splitKey(l.text)
		if !ok {
			return nil, i, fmt.Errorf("baris %d: bukan pasangan \"kunci: nilai\" — %q", l.no, l.text)
		}
		i++
		if rest != "" {
			m[key], _ = parseScalar(rest)
			continue
		}
		// Nilai ada di baris berikutnya: mapping anak, list anak, atau null.
		if i < len(ls) && ls[i].indent > indent {
			v, next, err := parseBlock(ls, i, ls[i].indent)
			if err != nil {
				return nil, next, err
			}
			m[key] = v
			i = next
			continue
		}
		// List anak boleh ditulis sejajar dengan kunci (indentasi sama).
		if i < len(ls) && ls[i].indent == indent && strings.HasPrefix(ls[i].text, "- ") {
			v, next, err := parseList(ls, i, indent)
			if err != nil {
				return nil, next, err
			}
			m[key] = v
			i = next
			continue
		}
		m[key] = nil
	}
	return m, i, nil
}

func parseList(ls []yamlLine, i, indent int) (any, int, error) {
	var out []any
	for i < len(ls) {
		l := ls[i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, i, fmt.Errorf("baris %d: indentasi meleset di dalam list", l.no)
		}
		if !strings.HasPrefix(l.text, "- ") && l.text != "-" {
			break
		}
		rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		i++
		if rest == "" {
			// Elemen adalah blok baris berikutnya (mapping multiline).
			if i < len(ls) && ls[i].indent > indent {
				v, next, err := parseBlock(ls, i, ls[i].indent)
				if err != nil {
					return nil, next, err
				}
				out = append(out, v)
				i = next
				continue
			}
			out = append(out, nil)
			continue
		}
		// "- key: value" — mapping yang dimulai di baris yang sama dengan
		// penanda list. Sisanya dibaca sebagai blok dengan indentasi atau
		// "virtual" sebesar kolom setelah "- ".
		if k, v, ok := splitKey(rest); ok {
			item := map[string]any{}
			if v != "" {
				item[k], _ = parseScalar(v)
			} else if i < len(ls) && ls[i].indent > indent {
				child, next, err := parseBlock(ls, i, ls[i].indent)
				if err != nil {
					return nil, next, err
				}
				item[k] = child
				i = next
			} else {
				item[k] = nil
			}
			// Sisa key untuk elemen yang sama, sejajar dengan k.
			for i < len(ls) && ls[i].indent == indent+2 && !strings.HasPrefix(ls[i].text, "- ") {
				l2 := ls[i]
				k2, v2, ok2 := splitKey(l2.text)
				if !ok2 {
					break
				}
				i++
				if v2 != "" {
					item[k2], _ = parseScalar(v2)
				} else if i < len(ls) && ls[i].indent > l2.indent {
					child, next, err := parseBlock(ls, i, ls[i].indent)
					if err != nil {
						return nil, next, err
					}
					item[k2] = child
					i = next
				} else {
					item[k2] = nil
				}
			}
			out = append(out, item)
			continue
		}
		sv, _ := parseScalar(rest)
		out = append(out, sv)
	}
	return out, i, nil
}

// splitKey memecah "key: value". Kunci yang mengandung tanda kutip dibaca
// sampai kutip penutup, supaya "Bearer a: b" tidak terpotong di titik dua.
func splitKey(s string) (key, val string, ok bool) {
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		q := s[0]
		if end := strings.IndexByte(s[1:], q); end >= 0 {
			rest := strings.TrimSpace(s[end+2:])
			if !strings.HasPrefix(rest, ":") {
				return "", "", false
			}
			return s[1 : end+1], stripComment(strings.TrimSpace(rest[1:])), true
		}
		return "", "", false
	}
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", false
	}
	// "https://x" bukan key: value, yang sebelum titik dua bukan identifier
	// yang masuk akal kalau berisi "//".
	if idx+1 < len(s) && s[idx+1] != ' ' {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), stripComment(strings.TrimSpace(s[idx+1:])), true
}

// stripComment membuang komentar di akhir nilai. Tanda '#' hanya dianggap
// komentar kalau di awal atau didahului spasi — supaya token seperti
// "abc#def" tetap utuh.
func stripComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ') {
			return strings.TrimSpace(s[:i])
		}
	}
	return s
}

func parseScalar(s string) (any, bool) {
	if s == "" {
		return nil, true
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1], true
		}
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	case "null", "~":
		return nil, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, true
	}
	return s, true
}

// ── akses helper ───────────────────────────────────────────────────────────

// AsMap taking value sebagai map. Mengembalikan error, bukan map kosong,
// supaya config yang salah bentuknya ketahuan alih-alih diam-diam dipakai
// dengan target kosong.
func AsMap(v any, path string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: harus berupa mapping, dapat %s", path, typeName(v))
	}
	return m, nil
}

// AsList taking value sebagai list.
func AsList(v any, path string) ([]any, error) {
	if v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: harus berupa list, dapat %s", path, typeName(v))
	}
	return l, nil
}

// AsString mengambil nilai sebagai string.
//
// Angka, float, dan bool ikut diterima dan diubah jadi teks. Alasannya
// pemakaian: di config, menulis "conc: 2" jauh lebih natural daripada
// 'conc: "2"', dan keduanya harus bisa dipakai tanpa efek berbeda.
func AsString(v any, path string) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case nil:
		return "", nil
	case int:
		return strconv.Itoa(t), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(t), nil
	default:
		return "", fmt.Errorf("%s: harus berupa teks, dapat %s", path, typeName(v))
	}
}

// AsBool taking value sebagai bool. String "true"/"false" juga diterima
// karena sering diketik begitu di config.
func AsBool(v any, path string) (bool, error) {
	switch t := v.(type) {
	case bool:
		return t, nil
	case nil:
		return false, nil
	case string:
		switch strings.ToLower(t) {
		case "true", "yes", "on":
			return true, nil
		case "false", "no", "off":
			return false, nil
		}
	}
	return false, fmt.Errorf("%s: harus berupa true/false, dapat %s", path, typeName(v))
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "kosong"
	case map[string]any:
		return "mapping"
	case []any:
		return "list"
	case string:
		return "teks"
	case bool:
		return "bool"
	case int:
		return "angka bulat"
	case float64:
		return "angka"
	default:
		return "tipe tidak dikenal"
	}
}

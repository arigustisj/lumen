package lumen

import (
	"reflect"
	"testing"
)

// TestYAMLSubsetDasar — bentuk yang paling sering dipakai di config lumen.
func TestYAMLSubsetDasar(t *testing.T) {
	src := `
# komentar di awal
targets:
  - name: parama-stag
    url: https://parama-stag.coba-sam.com
    authz: true
    tokens:
      as_user_a: "Bearer aaa.111"
      anonymous: true

  - name: internal
    url: https://svc.kantor.internal:8443
    authz: false

defaults:
  delay: 1s
  conc: 2
  timeout: 180
  probe: true
  tags: [a, b]        # flow list sengaja tidak didukung -> harus jadi teks
`
	got, err := ParseYAML(src)
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}

	ts, err := AsList(got["targets"], "targets")
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 2 {
		t.Fatalf("target count = %d, mau 2", len(ts))
	}

	t0, _ := AsMap(ts[0], "targets[0]")
	if n, _ := AsString(t0["name"], "n"); n != "parama-stag" {
		t.Errorf("name = %q", n)
	}
	if u, _ := AsString(t0["url"], "u"); u != "https://parama-stag.coba-sam.com" {
		t.Errorf("url = %q — tanda dua titik di URL harus tidak dipecah", u)
	}
	if a, _ := AsBool(t0["authz"], "a"); !a {
		t.Error("authz harus true")
	}

	tok, _ := AsMap(t0["tokens"], "tokens")
	if v, _ := AsString(tok["as_user_a"], "t"); v != "Bearer aaa.111" {
		t.Errorf("token = %q", v)
	}
	if v, _ := AsBool(tok["anonymous"], "anon"); !v {
		t.Error("anonymous harus true")
	}

	t1, _ := AsMap(ts[1], "targets[1]")
	if a, _ := AsBool(t1["authz"], "a"); a {
		t.Error("authz target kedua harus false")
	}

	d, _ := AsMap(got["defaults"], "defaults")
	if v, _ := AsString(d["delay"], "delay"); v != "1s" {
		t.Errorf("delay = %q", v)
	}
	if v, _ := AsString(d["conc"], "conc"); v != "2" {
		t.Errorf("conc = %q", v)
	}
	if v, _ := AsBool(d["probe"], "probe"); !v {
		t.Error("probe harus true")
	}
}

// TestYAMLListSederhana — list scalar di bawah kunci.
func TestYAMLListSederhana(t *testing.T) {
	got, err := ParseYAML("paths:\n  - /a\n  - /b\n  - /c\n")
	if err != nil {
		t.Fatal(err)
	}
	l, _ := AsList(got["paths"], "paths")
	want := []any{"/a", "/b", "/c"}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("paths = %#v, mau %#v", l, want)
	}
}

// TestYAMLKutipMencakupTandaDuaTitik — nilai yang mengandung ": " harus
// aman. Ini yang bikin "Bearer a: b" tidak hancur.
func TestYAMLKutipMencakupTandaDuaTitik(t *testing.T) {
	got, err := ParseYAML("t: \"Bearer abc: def\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := AsString(got["t"], "t"); v != "Bearer abc: def" {
		t.Errorf("t = %q", v)
	}
}

// TestYAMLKomentarTidakMemotongHashDiTengah — "#" di tengah token bukan
// komentar. Token JWT atau password bisa mengandung "#".
func TestYAMLKomentarTidakMemotongHashDiTengah(t *testing.T) {
	got, err := ParseYAML("t: abc#def   # ini komentar\n")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := AsString(got["t"], "t"); v != "abc#def" {
		t.Errorf("t = %q, mau abc#def", v)
	}
}

// TestYAMLTabDitolak — tab di indentasi menghasilkan hasil yang berbeda
// antara editor dan program. Lebih baik error daripada salah baca.
func TestYAMLTabDitolak(t *testing.T) {
	if _, err := ParseYAML("targets:\n\t- name: x\n"); err == nil {
		t.Fatal("harus menolak indentasi dengan tab")
	}
}

// TestYAMLIndentasiMelesetDitolak — indentasi tak terduga harus error,
// bukan diam-diam mengabaikan baris.
func TestYAMLIndentasiMelesetDitolak(t *testing.T) {
	if _, err := ParseYAML("a: 1\n      b: 2\n"); err == nil {
		t.Fatal("harus menolak indentasi yang meleset")
	}
}

// TestYAMLBarisBukanPasanganDitolak.
func TestYAMLBarisBukanPasanganDitolak(t *testing.T) {
	if _, err := ParseYAML("a: 1\nbaris liar tanpa titik dua\n"); err == nil {
		t.Fatal("harus menolak baris yang bukan pasangan kunci")
	}
}

// TestAsHelperMemberiErrorYangJelas — helper wajib melaporkan letak masalah,
// bukan mengembalikan nilai nol yang dipakai diam-diam.
func TestAsHelperMemberiErrorYangJelas(t *testing.T) {
	if _, err := AsList("bukan list", "targets"); err == nil {
		t.Error("AsList harus menolak string")
	}
	if _, err := AsMap([]any{1}, "targets"); err == nil {
		t.Error("AsMap harus menolak list")
	}
	if _, err := AsBool(42, "probe"); err == nil {
		t.Error("AsBool harus menolak angka")
	}
	if v, err := AsBool(nil, "probe"); err != nil || v {
		t.Errorf("AsBool(nil) = %v, %v; mau false, nil", v, err)
	}
	if v, err := AsList(nil, "targets"); err != nil || len(v) != 0 {
		t.Errorf("AsList(nil) = %v, %v", v, err)
	}
}

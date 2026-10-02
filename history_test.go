package lumen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repFor(target string) *Report {
	return &Report{
		Target:      target,
		GeneratedAt: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC),
		DurationMS:  4100,
		Pages:       []Page{{URL: target + "/", Status: 200}},
		Endpoints: []Endpoint{
			{Method: "GET", Path: "/api/a", Origin: OriginJS},
		},
		Findings: []Finding{
			{Title: "CSP tidak dikirim", Kind: "header", Severity: SevHigh,
				Where: target, Detail: "Tidak ada pembatasan asal skrip."},
			{Title: "X-Frame-Options tidak dikirim", Kind: "header", Severity: SevMedium,
				Where: target, Detail: "Halaman bisa di-embed iframe."},
		},
		Stats: map[string]int{"html": 1, "js": 1},
	}
}

func TestStoreMenyimpanTanpaMenimpa(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	b := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)

	r1, err := s.SaveRun(repFor("https://a.example"), a)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := s.SaveRun(repFor("https://a.example"), b)
	if err != nil {
		t.Fatal(err)
	}
	if r1.File == r2.File {
		t.Fatalf("dua scan target sama harus jadi dua berkas, keduanya %s", r1.File)
	}
	if len(s.Runs()) != 2 {
		t.Fatalf("harus ada 2 run, ada %d", len(s.Runs()))
	}
	// Terbaru dulu.
	if !s.Runs()[0].At.Equal(b) {
		t.Fatal("run terbaru harus di urutan pertama")
	}
}

func TestStoreReloadDariIndexDanDariBerkas(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	if _, err := s.SaveRun(repFor("https://a.example"), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Index dihapus: RebuildIndex harus bisa membangun ulang dari isi folder.
	if err := os.Remove(s.indexPath()); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenStore(dir)
	if err := s2.LoadIndex(); err != nil {
		t.Fatal(err)
	}
	if len(s2.Runs()) != 0 {
		t.Fatal("index yang hilang harus dibaca sebagai kosong, bukan error")
	}
	n, err := s2.RebuildIndex()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("RebuildIndex harus menemukan 1 run, menemukan %d", n)
	}

	// Isi laporan harus kembali utuh.
	rep, err := s2.LoadRun(s2.Runs()[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 2 {
		t.Fatalf("laporan harus punya 2 temuan, punya %d", len(rep.Findings))
	}
	if rep.Findings[0].Title != "CSP tidak dikirim" {
		t.Fatalf("judul temuan hilang setelah round-trip: %q", rep.Findings[0].Title)
	}
}

func TestStoreBerkasTidakDapatDibacaOlehOrangLain(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	if _, err := s.SaveRun(repFor("https://a.example"), time.Now()); err != nil {
		t.Fatal(err)
	}
	r := s.Runs()[0]
	for _, p := range []string{
		filepath.Join(dir, r.File),
		filepath.Join(dir, "index.json"),
	} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %#o, harus tidak bisa dibaca kelompok lain", p, fi.Mode().Perm())
		}
	}
}

func TestSlugAmanUntukNamaFolder(t *testing.T) {
	cases := map[string]string{
		"https://parama-stag.coba-sam.com": "parama-stag.coba-sam.com",
		"http://10.0.0.5:8080/admin":       "10.0.0.5-8080-admin",
		"https://a.b/c?x=1&y=2":            "a.b-c-x-1-y-2",
	}
	for in, want := range cases {
		if got := slugify(in); got != want {
			t.Errorf("slugify(%q) = %q, ingin %q", in, got, want)
		}
	}
}

func TestMarkdownMemuatYangPenting(t *testing.T) {
	rep := repFor("https://a.example")
	rep.Candidates = Classify(rep.Endpoints, rep.Findings)
	rep.Coverage = BuildCoverage(*rep)
	run := Run{Target: rep.Target, At: rep.GeneratedAt, File: "a.example/x.json", Endpoints: 1, Findings: 2, High: 1}

	path := t.TempDir() + "/r.md"
	if err := WriteMarkdown(path, rep, rep.Candidates, rep.Coverage, run); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)

	must := []string{
		"schema: lumen/1",
		"target: https://a.example",
		"verdict:",
		"CSP tidak dikirim",
		"Tidak ada pembatasan asal skrip.",
		"## Cakupan",
		"### Yang TIDAK dianalisis",
		"scanned_at: 2026-10-02",
	}
	for _, w := range must {
		if !strings.Contains(md, w) {
			t.Errorf("laporan markdown tidak memuat %q", w)
		}
	}

	// Bagian penutup laporan harus menyatakan batasnya, bukan berhenti di
	// daftar temuan. Tanpa ini "tidak menemukan apa-apa" dan "tidak sempat
	// memeriksa" menjadi kalimat yang sama.
	if !strings.Contains(md, "inject") {
		t.Error("bagian yang tidak dianalisis wajib menyebut injeksi")
	}
}

func TestMarkdownMenyatakanKegagalanScan(t *testing.T) {
	rep := repFor("https://a.example")
	rep.RootError = `dial tcp: lookup a.example: no such host`
	rep.Findings = nil
	rep.Endpoints = nil
	rep.Coverage = BuildCoverage(*rep)
	run := Run{Target: rep.Target, At: rep.GeneratedAt, File: "a/x.json"}

	path := t.TempDir() + "/r.md"
	if err := WriteMarkdown(path, rep, nil, rep.Coverage, run); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	md := string(b)
	if !strings.Contains(md, "SCAN GAGAL") {
		t.Error("scan gagal harus dinyatakan eksplisit di laporan")
	}
	if !strings.Contains(md, "tidak boleh dianggap") {
		t.Error("peringatan salah tafsir harus ikut tertulis")
	}
}

func TestMarkdownTidakMengulangKandidatPerEndpoint(t *testing.T) {
	var cands []Candidate
	for i := 0; i < 40; i++ {
		cands = append(cands, Candidate{
			ID: "api1-bola", Category: "API1:2023", Title: "Broken Object Level Authorization",
			Confidence: "high", Signal: "path dengan id", Verify: "cek dua akun",
		})
	}
	rep := repFor("https://a.example")
	rep.Coverage = BuildCoverage(*rep)
	run := Run{Target: rep.Target, At: rep.GeneratedAt, File: "a/x.json"}

	path := t.TempDir() + "/r.md"
	if err := WriteMarkdown(path, rep, cands, rep.Coverage, run); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	md := string(b)
	if n := strings.Count(md, "### API1:2023"); n != 1 {
		t.Fatalf("40 kandidat satu aturan harus jadi 1 bagian, jadi %d bagian", n)
	}
	if !strings.Contains(md, "40 kandidat dari 1 aturan") {
		t.Error("jumlah kandidat dan jumlah aturan harus keduanya disebut")
	}
}

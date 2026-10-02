package lumen

import (
	"strings"
	"testing"
)

// TestClassifyBolaAdalahYangP fruitful — BOLA (API1) adalah kelas temuan
// paling bernilai di API modern dan paling sering terlewat, karena tesnya
// butuh dua akun. lengthwise yang paling sering luput adalah path dengan
// parameter objek: endpoint seperti /api/orders/{id} terlihat "aman" karena
// ada autentikasi, padahal yang diotorisasi adalah TOKEN, bukan KEPEMILIKAN
// objek.
func TestClassifyBolaPalingFruitful(t *testing.T) {
	eps := []Endpoint{
		{Path: "/api/orders/${id}", Method: "GET", Origin: OriginJS, Flags: []string{"path-berisi-parameter"}},
		{Path: "/api/orders", Method: "GET", Origin: OriginJS},
	}
	cands := Classify(eps, nil)

	var bola *Candidate
	for i := range cands {
		if cands[i].Category == "API1:2023" && cands[i].Where == "/api/orders/${id}" {
			bola = &cands[i]
		}
	}
	if bola == nil {
		t.Fatal("path dengan parameter objek tidak diklasifikasikan sebagai kandidat BOLA")
	}
	// Kandidat tanpa langkah verifikasi hanya tebakan.
	if !strings.Contains(strings.ToLower(bola.Verify), "user") {
		t.Errorf("Verify harus menjelaskan cara menguji dengan dua user, dapat: %q", bola.Verify)
	}
	if bola.Remediate == "" {
		t.Error("kandidat tanpa saran perbaikan tidak bisa ditindaklanjuti")
	}
	// Path tanpa parameter tidak boleh jadi kandidat BOLA.
	for _, c := range cands {
		if c.Category == "API1:2023" && c.Where == "/api/orders" {
			t.Error("path tanpa parameter objek salah diklasifikasikan sebagai BOLA")
		}
	}
}

func TestClassifyBFLAUntukAdminTanpaAuth(t *testing.T) {
	eps := []Endpoint{
		{Path: "/admin/users", Method: "DELETE", Origin: OriginJS, Flags: []string{"AKSES-TANPA-AUTH"}},
		{Path: "/admin/settings", Method: "GET", Origin: OriginJS, Flags: []string{"terproteksi-auth"}},
	}
	cands := Classify(eps, nil)

	var open, prot *Candidate
	for i := range cands {
		if cands[i].Category != "API5:2023" {
			continue
		}
		if cands[i].Where == "/admin/users" {
			open = &cands[i]
		}
		if cands[i].Where == "/admin/settings" {
			prot = &cands[i]
		}
	}
	if open == nil || open.Confidence != "high" {
		t.Errorf("admin endpoint tanpa auth harus confidence high, dapat %+v", open)
	}
	if prot == nil || prot.Confidence != "low" {
		t.Errorf("admin endpoint terproteksi auth harus confidence low, dapat %+v", prot)
	}
	// Urutan: high di atas low. Kalau tidak, daftar yang ditampilkan di
	// terminal mengaburkan yang paling penting.
	if len(cands) >= 2 && cands[0].Confidence != "high" {
		t.Errorf("kandidat highest high harus diurutkan pertama, dapat %q", cands[0].Confidence)
	}
}

// TestClassifyTidakMengarangBukti — ini yang menjaga lumen tetap jujur.
// Skor confidence hanya boleh naik karena sinyal yang benar-benar diamati.
func TestClassifyTidakMengarangBukti(t *testing.T) {
	// Endpoint yang HANYA terlihat sebagai string di bundle, tanpa probe.
	eps := []Endpoint{{Path: "/admin/x", Method: "GET", Origin: OriginJS}}
	for _, c := range Classify(eps, nil) {
		if c.Confidence == "high" {
			t.Errorf("kandidat %q dapat confidence high tanpa probe sama sekali — itu mengarang bukti", c.Where)
		}
		if strings.Contains(c.Signal, "tanpa auth") {
			t.Errorf("Signal %q mengklaim sesuatu yang belum diamati", c.Signal)
		}
	}
}

func TestCoverageMenyebutYangTidakDiuji(t *testing.T) {
	cov := BuildCoverage(Report{Stats: map[string]int{"bundle": 1}})

	if len(cov.NotTested) == 0 {
		t.Fatal("Coverage.NotTested kosong — laporan tanpa ini bisa disalahartikan sebagai 'aman'")
	}
	joined := strings.ToLower(strings.Join(cov.NotTested, " "))
	// BOLA butuh dua akun; itu kelemahan alat ini dan harus tertulis.
	if !strings.Contains(joined, "dua akun") {
		t.Errorf("Coverage harus menyebut keterbatasan otorisasi, dapat: %v", cov.NotTested)
	}
	if !strings.Contains(joined, "login") {
		t.Errorf("Coverage harus menyebut lumen tidak melakukan login, dapat: %v", cov.NotTested)
	}

	// Tanpa bundle, batasannya harus lebih serius.
	cov2 := BuildCoverage(Report{Stats: map[string]int{}})
	if !strings.Contains(strings.Join(cov2.Limits, " "), "TIDAK ADA bundle") {
		t.Errorf("tanpa bundle, Coverage.Limits harus memperingatkan analisis JS dilewati, dapat: %v", cov2.Limits)
	}
}

// TestSARIFLevelNote — kandidat statis harus level "note".
//
// Kalau dinaikkan ke "error", GitHub code scanning akan beralarm atas hal
// yang belum diperiksa, dan orang lalu mematikan alarmnya seluruhnya. Itu
// skenario yang lebih buruk daripada tidak ada output.
func TestSARIFLevelNote(t *testing.T) {
	eps := []Endpoint{
		{Path: "/admin/${id}", Method: "DELETE", Origin: OriginJS, Flags: []string{"AKSES-TANPA-AUTH"}},
	}
	cands := Classify(eps, nil)
	log := BuildSARIF(Report{Target: "https://x.test", Stats: map[string]int{"bundle": 1}},
		cands, BuildCoverage(Report{Stats: map[string]int{"bundle": 1}}), 2)

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, harus 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("$schema wajib diisi di SARIF 2.1.0")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, harus 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != Name || run.Tool.Driver.Version != Version {
		t.Errorf("driver = %s %s, harus %s %s", run.Tool.Driver.Name, run.Tool.Driver.Version, Name, Version)
	}
	if len(run.Results) == 0 {
		t.Fatal("tidak ada result, padahal ada kandidat")
	}
	for _, r := range run.Results {
		if r.Level != "note" {
			t.Errorf("result %s level = %q, harus note (kandidat belum terbukti)", r.RuleID, r.Level)
		}
		if r.Fingerprints["lumen/v1"] == "" {
			t.Errorf("result %s tanpa fingerprint — platform tidak bisa melacak temuan antar-run", r.RuleID)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("result %s ruleIndex %d di luar jangkauan rules", r.RuleID, r.RuleIndex)
		}
	}
	// Cakupan harus ikut, karena SARIF tidak punya tempat untuk "tidak diuji".
	if run.Properties == nil || run.Properties["coverage"] == nil {
		t.Error("properties.coverage wajib diisi; tanpa itu hasil kosong terlihat sama dengan hasil bersih")
	}
	if len(run.Invocations) != 1 || run.Invocations[0].ExitCode != 2 {
		t.Errorf("invocations salah, harus exitCode 2: %+v", run.Invocations)
	}
}

// TestFingerprintStabil — kalau berubah tiap scan, setiap temuan terbaca
// sebagai temuan baru dan code scanning penuh diff palsu.
func TestFingerprintStabil(t *testing.T) {
	a := fingerprint("API1:2023", "/api/x/${id}")
	b := fingerprint("API1:2023", "/api/x/${id}")
	if a != b {
		t.Errorf("fingerprint tidak deterministik: %q vs %q", a, b)
	}
	if a == fingerprint("API5:2023", "/api/x/${id}") {
		t.Error("kategori berbeda harus punya fingerprint berbeda")
	}
	if a == fingerprint("API1:2023", "/api/y/${id}") {
		t.Error("path berbeda harus punya fingerprint berbeda")
	}
	if len(a) != 16 {
		t.Errorf("panjang fingerprint = %d, harus 16", len(a))
	}
}

// TestExitCodeMembedakanScanGagal — tanpa exit code khusus, scan yang gagal
// membaca target terlihat IDENTIK dengan scan yang bersih.
func TestExitCodeMembedakanScanGagal(t *testing.T) {
	// Bundle tidak terbaca = analyze JS dilewati total.
	if got := ExitCode(Report{Stats: map[string]int{}}, nil); got != 3 {
		t.Errorf("tanpa bundle exit = %d, harus 3 (scan tidak bisa dipercaya)", got)
	}
	// Ada kandidat high.
	cands := []Candidate{{Confidence: "high"}}
	if got := ExitCode(Report{Stats: map[string]int{"bundle": 1}}, cands); got != 2 {
		t.Errorf("kandidat high exit = %d, harus 2", got)
	}
	// Hanya kandidat low.
	if got := ExitCode(Report{Stats: map[string]int{"bundle": 1}},
		[]Candidate{{Confidence: "low"}}); got != 0 {
		t.Errorf("hanya kandidat low exit = %d, harus 0", got)
	}
}

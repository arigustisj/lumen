package lumen

import (
	"strings"
	"testing"
	"time"
)

func mkReport(at time.Time, pages int, eps []string, finds []Finding, rootErr string) *Report {
	r := &Report{
		Target:      "https://a.example",
		GeneratedAt: at,
		RootError:   rootErr,
		Stats:       map[string]int{},
	}
	for i := 0; i < pages; i++ {
		r.Pages = append(r.Pages, Page{URL: "https://a.example/p"})
	}
	for _, e := range eps {
		m, p, _ := strings.Cut(e, " ")
		r.Endpoints = append(r.Endpoints, Endpoint{Method: m, Path: p})
	}
	r.Findings = finds
	return r
}

var (
	t1 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
)

func TestDiffMenandaiTemuanBaruDanHilang(t *testing.T) {
	old := mkReport(t1, 3, []string{"GET /a", "GET /b"},
		[]Finding{{Title: "CSP tidak dikirim", Kind: "header", Severity: SevHigh}}, "")
	nw := mkReport(t2, 3, []string{"GET /b", "GET /c"},
		[]Finding{{Title: "HSTS tidak dikirim", Kind: "header", Severity: SevHigh},
			{Title: "XFO tidak dikirim", Kind: "header", Severity: SevMedium}}, "")

	d := DiffReports(old, nw)

	if len(d.NewFindings) != 2 {
		t.Errorf("harus ada 2 temuan baru, ada %d", len(d.NewFindings))
	}
	if len(d.ResolvedFindings) != 1 || d.ResolvedFindings[0].Title != "CSP tidak dikirim" {
		t.Errorf("temuan CSP harus tercatat hilang, dapat %+v", d.ResolvedFindings)
	}
	// Temuan baru harus urut dari yang paling serius.
	if d.NewFindings[0].Title != "HSTS tidak dikirim" {
		t.Errorf("urutan temuan baru salah: %s di depan", d.NewFindings[0].Title)
	}
	if d.SeverityDelta[SevHigh] != 0 || d.SeverityDelta[SevMedium] != 1 {
		t.Errorf("delta severity salah: high=%d medium=%d",
			d.SeverityDelta[SevHigh], d.SeverityDelta[SevMedium])
	}
}

func TestDiffEndpointMethodBerbedaTerpisah(t *testing.T) {
	old := mkReport(t1, 1, []string{"GET /api/user"}, nil, "")
	nw := mkReport(t2, 1, []string{"POST /api/user"}, nil, "")

	d := DiffReports(old, nw)
	if len(d.NewEndpoints) != 1 || d.NewEndpoints[0] != "POST /api/user" {
		t.Fatalf("endpoint dengan method berbeda harus dianggap baru, dapat %v", d.NewEndpoints)
	}
	if len(d.RemovedEndpoints) != 1 || d.RemovedEndpoints[0] != "GET /api/user" {
		t.Fatalf("endpoint lama harus tercatat hilang, dapat %v", d.RemovedEndpoints)
	}
}

func TestDiffTidakMenyebutPerbaikanKalauScanBaruLebihDangkal(t *testing.T) {
	// Scan lama menjangkau 10 halaman dan menemukan banyak endpoint.
	// Scan baru hanya menjangkau 2 halaman — kemungkinan besar gagal
	// separuh jalan, bukan aplikasinya yang diperbaiki.
	old := mkReport(t1, 10, []string{"GET /a", "GET /b", "GET /c"}, nil, "")
	nw := mkReport(t2, 2, []string{"GET /a"}, nil, "")

	d := DiffReports(old, nw)

	if d.CoverageComparable {
		t.Fatal("cakupan yang berbeda harus menandai diff tidak sebanding")
	}
	if len(d.RemovedEndpoints) == 0 {
		t.Fatal("endpoint tetap harus dilaporkan hilang, tapi harus ada peringatan")
	}
	if !strings.Contains(d.CoverageNote, "halaman turun") {
		t.Errorf("peringatan cakupan kurang jelas: %q", d.CoverageNote)
	}
}

func TestDiffMenyatakanGagalnyaScanBaru(t *testing.T) {
	old := mkReport(t1, 5, []string{"GET /a", "GET /b"}, nil, "")
	nw := mkReport(t2, 0, nil, nil, "dial tcp: lookup a.example: no such host")

	d := DiffReports(old, nw)

	if d.CoverageComparable {
		t.Fatal("scan yang gagal total tidak boleh dibandingkan")
	}
	if !strings.Contains(d.CoverageNote, "gagal mengambil halaman awal") {
		t.Errorf("peringatan kegagalan scan tidak muncul: %q", d.CoverageNote)
	}
	// Ini yang paling rawan: tanpa peringatan, ini terbaca sebagai
	// "semua endpoint hilang", yang jauh lebih berbahaya daripada tidak ada.
	if len(d.RemovedEndpoints) != 2 {
		t.Fatalf("dua endpoint lama harus tercatat, dapat %d", len(d.RemovedEndpoints))
	}
}

func TestDiffTidakBeriFalsePositifPadaPerbedaanSesaat(t *testing.T) {
	// Selisih kecil (<30%) dalam jumlah halaman Artisan bukan perubahan cakupan.
	old := mkReport(t1, 10, []string{"GET /a", "GET /b"}, nil, "")
	nw := mkReport(t2, 8, []string{"GET /a", "GET /b"}, nil, "")

	d := DiffReports(old, nw)
	if !d.CoverageComparable {
		t.Errorf("selisih kecil seharusnya masih sebanding, catatan: %q", d.CoverageNote)
	}
}

func TestDiffKosongTapiTetapBisaDibaca(t *testing.T) {
	old := mkReport(t1, 2, []string{"GET /a"}, nil, "")
	nw := mkReport(t2, 2, []string{"GET /a"}, nil, "")

	d := DiffReports(old, nw)
	if d.HasChanges() {
		t.Error("tidak ada perubahan berarti HasChanges harus false")
	}
	if !strings.Contains(d.Summary(), "tidak ada perubahan") {
		t.Errorf("ringkasan harus menyatakan tidak ada perubahan: %q", d.Summary())
	}
}

func TestDiffMenambahFlagPerLaporanBaru(t *testing.T) {
	old := mkReport(t1, 3, []string{"GET /a"}, nil, "")
	nw := mkReport(t2, 3, []string{"GET /a"},
		[]Finding{{Title: "Secret di bundle", Kind: "kredensial", Severity: SevHigh}}, "")

	d := DiffReports(old, nw)
	if !d.HasChanges() {
		t.Fatal("temuan baru harus terdeteksi sebagai perubahan")
	}
	if d.SeverityDelta[SevHigh] != 1 {
		t.Errorf("delta high harus naik 1, dapat %d", d.SeverityDelta[SevHigh])
	}
}

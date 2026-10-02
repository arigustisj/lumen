package lumen

import (
	"testing"
	"time"
)

// TestIndexTidakDitimpaAntarProses — regresi untuk bug yang menghapus riwayat.
//
// Store baru dibuat di setiap pemanggilan CLI. Kalau SaveRun tidak memuat
// index lebih dulu, setiap proses menulis index yang hanya berisi run-nya
// sendiri, dan riwayat target tinggal satu item padahal semua berkas masih ada.
//
// Tidak ada error, tidak ada peringatan. Diff antar scan selalu membaca
// "scan pertama" sebagai baseline karena tidak pernah ada scan kedua.
func TestIndexTidakDitimpaAntarProses(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		s, err := OpenStore(dir) // store baru, simulating proses baru
		if err != nil {
			t.Fatal(err)
		}
		// Sengaja tidak memanggil LoadIndex — itulah kondisi CLI sebenarnya.
		if _, err := s.SaveRun(repFor("https://a.example"),
			time.Date(2026, 10, 2, 10, i, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := OpenStore(dir)
	if err := s.LoadIndex(); err != nil {
		t.Fatal(err)
	}
	if len(s.Runs()) != 3 {
		t.Fatalf("tiga proses menulis tiga run; index harus berisi 3, berisi %d", len(s.Runs()))
	}
	_, older, err := s.LatestTwo("https://a.example")
	if err != nil {
		t.Fatalf("LatestTwo: %v", err)
	}
	if older == nil {
		t.Fatal("harus ada run sebelumnya sebagai baseline diff")
	}
}

// TestDiff uniting: run kedua harus bisa dibandingkan dengan run pertama.
func TestRunKeduaDapatDibandingkanDenganPertama(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	if _, err := s.SaveRun(repFor("https://a.example"),
		time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	// Run kedua menambah satu endpoint dan satu temuan high.
	rep2 := repFor("https://a.example")
	rep2.Endpoints = append(rep2.Endpoints,
		Endpoint{Method: "GET", Path: "/api/baru", Origin: OriginJS})
	rep2.Findings = append(rep2.Findings, Finding{
		Title: "Endpoint admin terbuka", Kind: "route", Severity: SevHigh,
		Where: "https://a.example", Detail: "...",
	})

	// Proses baru untuk scan kedua —店长 tanpa memuat index lebih dulu,
	// seperti yang terjadi setiap kali CLI dijalankan.
	s2, _ := OpenStore(dir)
	if _, err := s2.SaveRun(rep2, time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	// Proses ketiga: hanya membaca.
	s3, _ := OpenStore(dir)
	newer, older, err := s3.LatestTwo("https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	newRep, oldRep, err := s3.LoadPair(newer, older)
	if err != nil {
		t.Fatal(err)
	}
	d := DiffReports(oldRep, newRep)
	if len(d.NewEndpoints) != 1 || d.NewEndpoints[0] != "GET /api/baru" {
		t.Errorf("endpoint baru tidak terdeteksi: %v", d.NewEndpoints)
	}
	if len(d.NewFindings) != 1 {
		t.Errorf("temuan baru tidak terdeteksi: %d", len(d.NewFindings))
	}
}

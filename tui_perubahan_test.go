package lumen

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Panel Perubahan tidak boleh menampilkan "tidak ada perubahan" ketika yang
// sebenarnya adalah "belum ada yang dibandingkan".
//
// Kalimat keduanya berbeda arah: yang pertama kabar baik, yang kedua
// Rally belum tahu. Menukar keduanya membuat pembaca menyimpulkan aplikasi
// tidak berubah sejak update terakhir, padahal tidak ada scan sebelumnya
// sama sekali.
func TestPanelPerubahanMembedakanBelumAdaBaselineDariTidakBerubah(t *testing.T) {
	m := NewTUIModel("https://a.example")
	m.Seed(repFor("https://a.example"), nil, Coverage{}, nil)

	m.diff = nil
	out := stripANSI(renderPerubahan(m, 80, 40))
	if !strings.Contains(out, "belum ada yang bisa dibandingkan") {
		t.Errorf("tanpa baseline panel harus menyatakan belum ada yang dibandingkan, dapat:\n%s", out)
	}
	if strings.Contains(out, "tidak ada perubahan") {
		t.Error("tanpa baseline tidak boleh menampilkan 'tidak ada perubahan'")
	}

	m.diff = &DiffResults{OldAt: "2026-10-01 10:00", KeptEndpoints: 3, KeptFindings: 2, CoverageComparable: true}
	out = stripANSI(renderPerubahan(m, 80, 40))
	if !strings.Contains(out, "tidak ada perubahan") {
		t.Errorf("dengan baseline yang sama, panel harus menampilkan tidak ada perubahan, dapat:\n%s", out)
	}
}

// Peringatan cakupan harus mendahului daftar perubahan, dan label "hilang"
// harus diganti.
func TestPanelPerubahanMenegurCakupanTidakSebanding(t *testing.T) {
	m := NewTUIModel("https://a.example")
	oldRep := repFor("https://a.example")
	newRep := repFor("https://a.example")
	newRep.Pages = nil
	newRep.Endpoints = nil
	newRep.Findings = nil
	newRep.RootError = "dial tcp: no such host"
	d := DiffReports(oldRep, newRep)
	m.diff = &d

	out := stripANSI(renderPerubahan(m, 80, 40))
	warn := strings.Index(out, "⚠")
	firstList := strings.Index(out, "TIDAK TERLIHAT")
	if warn < 0 {
		t.Errorf("peringatan cakupan harus ada:\n%s", out)
	}
	if firstList < 0 {
		t.Errorf("endpoint yang tidak terlihat harus dilabeli demikian:\n%s", out)
	}
	if warn > firstList {
		t.Error("peringatan cakupan harus muncul sebelum daftar perubahan")
	}
	if strings.Contains(out, "ENDPOINT HILANG") {
		t.Error("label 'ENDPOINT HILANG' tidak boleh dipakai saat cakupan tidak sebanding")
	}
}

// Baris ringkasan panel harus muat di terminal sempit.
func TestPanelPerubahanMuatDiTerminalSempit(t *testing.T) {
	m := NewTUIModel("https://a.example")
	m.Seed(repFor("https://a.example"), nil, Coverage{}, nil)
	m.diff = &DiffResults{
		OldAt: "2026-10-01 10:00", CoverageComparable: true,
		NewEndpoints:  []string{"GET /api/admin/users-yang-panjang-sekali"},
		NewFindings:   []Finding{{Title: "Endpoint admin terbuka tanpa batas", Severity: SevHigh}},
		KeptEndpoints: 10, KeptFindings: 5,
		SeverityDelta: map[Severity]int{SevHigh: 1},
	}
	for _, w := range []int{40, 56, 80, 120} {
		out := stripANSI(renderPerubahan(m, w, 40))
		for _, l := range strings.Split(out, "\n") {
			// Lebar diukur dalam kolom tampilan, bukan byte. "▲" occupying
			// tiga byte tapi hanya satu kolom di terminal — menghitung
			// byte akan melaporkan overflow palsu.
			got := lipgloss.Width(strings.TrimRight(l, " "))
			if got > w {
				t.Errorf("lebar %d: baris occupying %d kolom > %d: %q", w, got, w, l)
			}
		}
	}
}

func stripANSI(s string) string {
	var out strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc && (r == 'm' || r == 'M' || r == 'K'):
			inEsc = false
		case inEsc:
			// lewati
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

var _ = time.Now

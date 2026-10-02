package lumen

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Gaya lokal untuk panel ini. Sengaja terpisah dari gaya global supaya
// perubahan warna di satu panel tidak diam-diam mengubah panel lain.
var (
	stHigh = lipgloss.NewStyle().Foreground(cHigh)
	stGood = lipgloss.NewStyle().Foreground(cLow)
	stMed  = lipgloss.NewStyle().Foreground(cMedium)
	stMedW = lipgloss.NewStyle().Foreground(cMedium).Bold(true)
)

// renderPerubahan menampilkan selisih terhadap scan sebelumnya.
//
// Tiga kondisi harus dibedakan, karena ketiganya berbeda artinya:
//
//	ada perubahan        → daftar perubahan
//	tidak ada perubahan  → kabar baik, boleh singkat
//	tidak ada baseline   → belum bisa dinilai, BUKAN "tidak ada perubahan"
//
// Yang terakhir adalah yang berbahaya. Kalau panel menampilkan "tidak ada
// perubahan" saat baseline-nya belum ada, pembaca menyimpulkan aplikasinya
// tidak berubah sejak update terakhir — padahal tidak ada yang dibandingkan
// sama sekali.
func renderPerubahan(m *TUIModel, w, _ int) string {
	if m.diff == nil {
		return renderBelumAdaBaseline(m)
	}
	d := *m.diff
	if !d.HasChanges() {
		return renderTidakBerubah(d)
	}
	return renderDaftarPerubahan(d, w)
}

func renderBelumAdaBaseline(m *TUIModel) string {
	var b strings.Builder
	b.WriteString("\n  " + stMedW.Render("belum ada yang bisa dibandingkan") + "\n\n")
	b.WriteString("  " + stDim.Render("target  "+stripScheme(targetOf(m))) + "\n")
	b.WriteString("  " + stDim.Render("baru satu kali scan, jadi belum ada pembanding") + "\n")
	b.WriteString("  " + stDim.Render("pindai lagi — perubahan akan muncul di sini") + "\n")
	return b.String()
}

func renderTidakBerubah(d DiffResults) string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + stGood.Render("tidak ada perubahan") + "\n")
	b.WriteString("  " + stDim.Render("sejak "+d.OldAt) + "\n\n")
	b.WriteString("  " + stDim.Render(fmt.Sprintf("%d endpoint dan %d temuan tetap sama",
		d.KeptEndpoints, d.KeptFindings)) + "\n")
	return b.String()
}

func renderDaftarPerubahan(d DiffResults, w int) string {
	var b strings.Builder

	// Peringatan cakupan mendahului daftar perubahan. Daftar di bawahnya
	// bisa jadi artefak scan, dan itu harus diketahui sebelum dibaca.
	//
	// Teksnya dibungkus, bukan dipotong: kalimat peringatan yang terpotong
	// di tengah kata justru membuat Warnings-nya kehilangan bagian yang
	// paling menentukan — yaitu yang mana yang "belum tentu".
	if !d.CoverageComparable {
		b.WriteString("\n")
		for i, ln := range wrapN("⚠ "+d.CoverageNote, w-4) {
			if i == 0 {
				b.WriteString("  " + stMedW.Render(ln) + "\n")
			} else {
				b.WriteString("    " + stMedW.Render(ln) + "\n")
			}
		}
		for _, ln := range wrapN("perubahan di bawah bisa jadi hasil scan yang tidak lengkap", w-6) {
			b.WriteString("  " + stDim.Render(ln) + "\n")
		}
	}

	// Delta severity paling atas: ini yang paling menentukan.
	var deltas []string
	for _, sev := range []Severity{SevHigh, SevMedium, SevLow, SevInfo} {
		dv := d.SeverityDelta[sev]
		if dv == 0 {
			continue
		}
		sign := "+"
		if dv < 0 {
			sign = ""
		}
		txt := fmt.Sprintf("%s%d %s", sign, dv, sev)
		switch {
		case sev == SevHigh && dv > 0:
			deltas = append(deltas, stHigh.Render(txt))
		case dv < 0:
			deltas = append(deltas, stGood.Render(txt))
		default:
			deltas = append(deltas, stMed.Render(txt))
		}
	}
	if len(deltas) > 0 {
		b.WriteString("\n  " + strings.Join(deltas, "   ") + "\n")
	}

	if len(d.NewFindings) > 0 {
		b.WriteString(sectionHead("TEMUAN BARU", len(d.NewFindings), stHigh))
		for _, f := range d.NewFindings {
			b.WriteString(stHigh.Render(itemLine("▲ ", findingTitle(f), w)) + "\n")
		}
		b.WriteString("\n")
	}

	if len(d.ResolvedFindings) > 0 {
		// Labelnya bukan "perbaikan". Tanpa bukti lain, hilangnya temuan
		// bisa berarti scan yang tidak tuntas.
		label, c := "TEMUAN HILANG", stGood
		if !d.CoverageComparable {
			label, c = "TEMUAN TIDAK MUNCUL LAGI", stDim
		}
		b.WriteString(sectionHead(label, len(d.ResolvedFindings), c))
		for _, f := range d.ResolvedFindings {
			b.WriteString(stDim.Render(itemLine("· ", findingTitle(f), w)) + "\n")
		}
		b.WriteString("\n")
	}

	if len(d.NewEndpoints) > 0 {
		b.WriteString(sectionHead("ENDPOINT BARU", len(d.NewEndpoints), stAccent))
		for _, e := range clipList(d.NewEndpoints, 10) {
			b.WriteString(stGood.Render(itemLine("+ ", e, w)) + "\n")
		}
		if n := len(d.NewEndpoints) - 10; n > 0 {
			b.WriteString("    " + stDim.Render(fmt.Sprintf("… %d lainnya", n)) + "\n")
		}
		b.WriteString("\n")
	}

	if len(d.RemovedEndpoints) > 0 {
		label := "ENDPOINT HILANG"
		if !d.CoverageComparable {
			label = "ENDPOINT TIDAK TERLIHAT"
		}
		b.WriteString(sectionHead(label, len(d.RemovedEndpoints), stDim))
		for _, e := range clipList(d.RemovedEndpoints, 10) {
			b.WriteString(stDim.Render(itemLine("- ", e, w)) + "\n")
		}
		if n := len(d.RemovedEndpoints) - 10; n > 0 {
			b.WriteString("    " + stDim.Render(fmt.Sprintf("… %d lainnya", n)) + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("  " + stDim.Render(fmt.Sprintf("%d endpoint tetap · %d temuan tetap",
		d.KeptEndpoints, d.KeptFindings)) + "\n")
	return b.String()
}

func sectionHead(label string, n int, style lipgloss.Style) string {
	return "\n  " + style.Render(label) + "  " + stDim.Render(fmt.Sprint(n)) + "\n"
}

// clipList membatasi jumlah item per daftar supaya panel tidak meluber.
func clipList(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

// truncateTitle memotong teks agar muat di w karakter.
func truncateTitle(s string, w int) string {
	if w < 6 {
		w = 6
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	return string(r[:w-1]) + "…"
}

// itemLine menyusun satu baris daftar dan memastikannya tidak melewati w.
//
// Indentasi dan penanda dihitung di dalam w, bukan di luarnya. Menghitung
// keduanya terpisah adalah sumber overflow yang khas: teksnya sudah dipotong
// sesuai "ruang yang tersedia", tapi ruang itu keliru karena indentasi belum
// dikurangi — dan HP adalah tempat paling sempit yang dipakai.
func itemLine(marker, text string, w int) string {
	const indent = 4
	room := w - indent - lipgloss.Width(marker)
	if room < 6 {
		room = 6
	}
	return strings.Repeat(" ", indent) + marker + truncateTitle(text, room)
}

func targetOf(m *TUIModel) string {
	if m.rep != nil {
		return m.rep.Target
	}
	return m.target
}

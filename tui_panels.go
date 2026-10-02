package lumen

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Isi panel. Semua fungsi ini harus mengembalikan teks polos (tanpa border)
// — border dan pemotongan ditangani oleh viewBody, supaya scroll konsisten
// di semua panel.

func renderRingkasan(m *TUIModel, w, _ int) string {
	if m.rep == nil {
		return stDim.Render("belum ada data")
	}
	rep := m.rep
	var b strings.Builder

	// Bar komposisi temuan. Ini bagian yang paling sering dicari duluan:
	// "berapa yang serius" harus terbaca tanpa menghitung.
	if total := len(rep.Findings); total > 0 {
		counts := map[Severity]int{}
		for _, f := range rep.Findings {
			counts[f.Severity]++
		}
		b.WriteString("  " + severityBar(counts, total, w-4) + "\n\n")
	}

	type kv struct{ k, v string }
	rows := []kv{
		{"target", stripScheme(rep.Target)},
		{"durasi", fmtDuration(rep.DurationMS)},
		{"halaman", fmt.Sprint(len(rep.Pages))},
		{"endpoint", fmt.Sprint(len(rep.Endpoints))},
		{"temuan", fmt.Sprint(len(rep.Findings))},
		{"kandidat OWASP", fmt.Sprint(len(m.cands))},
	}
	if len(m.authz) > 0 {
		n := 0
		for _, ar := range m.authz {
			n += ar.Tested
		}
		rows = append(rows, kv{"authz diuji", fmt.Sprint(n)})
	}
	if len(rep.ScopeDenied) > 0 {
		rows = append(rows, kv{"di luar scope", fmt.Sprint(len(rep.ScopeDenied)) + " ditolak"})
	}

	// Kunci diberi satu spasi lebih dari label terpanjang supaya nilai
	// tidak pernah menempel ke kunci.
	kw := 16
	if w < 40 {
		kw = 11
	}
	for _, r := range rows {
		// Nilai panjang dipotong, bukan nilai. Kunci yang dipotong membuat
		// baris tidak terbaca sama sekali.
		v := r.v
		if room := w - 4 - kw; room > 8 && lipgloss.Width(v) > room {
			v = truncRight(v, room)
		}
		b.WriteString("  " + stDim.Render(pad(r.k, kw)) +
			lipgloss.NewStyle().Foreground(cText).Render(v) + "\n")
	}

	// Ringkasan cakupan sengaja ada di panel paling atas, bukan hanya di
	// tab Cakupan. Cropulan yang tidak dibaca hilang begitu saja.
	if len(m.cov.NotTested) > 0 {
		b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Foreground(cMedium).
			Render(fmt.Sprintf("%d hal TIDAK diuji", len(m.cov.NotTested))) + "\n")
		for _, l := range firstN(m.cov.NotTested, 3) {
			for _, ln := range wrapN("· "+l, w-6) {
				b.WriteString("    " + stDim.Render(ln) + "\n")
			}
		}
		if len(m.cov.NotTested) > 3 {
			b.WriteString("    " + stDim.Render(fmt.Sprintf("… %d lainnya (tab Cakupan)", len(m.cov.NotTested)-3)) + "\n")
		}
	}
	return b.String()
}

func renderTemuan(m *TUIModel, w, _ int) string {
	if m.rep == nil || len(m.rep.Findings) == 0 {
		return "  " + stDim.Render("tidak ada temuan")
	}
	var b strings.Builder
	for _, f := range m.rep.Findings {
		tag := severityTag(f.Severity)
		b.WriteString("  " + tag + " " +
			lipgloss.NewStyle().Bold(true).Foreground(cText).Render(f.Kind) + "\n")
		b.WriteString("     " + stDim.Render(f.Where) + "\n")
		for i, ln := range wrapN(f.Detail, w-8) {
			prefix := "     "
			if i > 0 {
				prefix = "     "
			}
			b.WriteString(prefix + lipgloss.NewStyle().Foreground(cDim).Render(ln) + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderEndpoint(m *TUIModel, w, _ int) string {
	if m.rep == nil || len(m.rep.Endpoints) == 0 {
		return "  " + stDim.Render("tidak ada endpoint")
	}
	showFlags := w >= 62
	var b strings.Builder
	for _, ln := range wrapN(fmt.Sprintf("%d endpoint — yang tidak ada di HTML ditandai *", len(m.rep.Endpoints)), w-4) {
		b.WriteString("  " + stDim.Render(ln) + "\n")
	}
	b.WriteString("\n")
	for _, e := range m.rep.Endpoints {
		method := pad(e.Method, 6)
		mc := cAccent
		if e.Method == "GET" {
			mc = cLow
		} else if e.Method == "" {
			mc = cDim
		}
		// Room = lebar terminal dikurangi method(6) + spasi + indent(2),
		// lalu dikurangi kolom flag dan status kalau keduanya ditampilkan.
		room := w - 9
		if showFlags {
			room -= 14
		}
		if e.Status > 0 {
			room -= 5
		}
		if room < 10 {
			room = 10
		}
		line := lipgloss.NewStyle().Foreground(mc).Render(method) + " " + e.Path
		if lipgloss.Width(e.Path) > room {
			line = lipgloss.NewStyle().Foreground(mc).Render(method) + " " + truncRight(e.Path, room)
		}
		b.WriteString("  " + line)
		if showFlags && len(e.Flags) > 0 {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(cMedium).Render(truncRight(e.Flags[0], 12)))
		}
		if e.Origin == OriginJS {
			b.WriteString(" " + lipgloss.NewStyle().Foreground(cAccent).Render("*"))
		}
		if e.Status > 0 {
			b.WriteString(" " + stDim.Render(fmt.Sprint(e.Status)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func renderKandidat(m *TUIModel, w, _ int) string {
	if len(m.cands) == 0 {
		return "  " + stDim.Render("tidak ada kandidat")
	}
	var b strings.Builder
	b.WriteString("  " + stDim.Render("Kandidat dari sinyal statis — belum terbukti. Verifikasi manual tetap wajib.") + "\n\n")
	for _, c := range m.cands {
		n := c.Count()
		b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cAccent).
			Render(pad(fmt.Sprint(n), 4)) +
			lipgloss.NewStyle().Bold(true).Foreground(cText).Render(c.Category+"  "+c.Title) + "\n")
		b.WriteString("     " + stDim.Render(strings.Join(c.CWE, ", ")) + "\n")
		for _, ln := range wrapN(c.Signal, w-8) {
			b.WriteString("     " + lipgloss.NewStyle().Foreground(cDim).Render("sinyal: "+ln) + "\n")
		}
		b.WriteString("     " + lipgloss.NewStyle().Foreground(cMedium).Render("cek:   "+firstLine(c.Verify)) + "\n\n")
	}
	return b.String()
}

func renderAuthz(m *TUIModel, w, _ int) string {
	if len(m.authz) == 0 {
		return "  " + stDim.Render("pemeriksaan otorisasi tidak dijalankan") + "\n\n" +
			stDim.Render("Butuh -config dengan target authz: true dan minimal dua token.") + "\n" +
			stDim.Render("Lihat lumen.example.yaml.")
	}
	var b strings.Builder
	for _, ar := range m.authz {
		counts := map[string]int{}
		for _, r := range ar.Results {
			counts[r.Verdict]++
		}
		b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(ar.Target) +
			stDim.Render(fmt.Sprintf("  %d diuji, %d diskip", ar.Tested, ar.Skipped)) + "\n\n")
		var bits []string
		for _, v := range []string{"anon-terbuka", "bola-dicurigai", "auth-tidak-aktif"} {
			if counts[v] > 0 {
				bits = append(bits, fmt.Sprintf("%s %d", v, counts[v]))
			}
		}
		if len(bits) == 0 {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(cLow).Render("tidak ada perbedaan antar perspektif") + "\n\n")
			continue
		}
		b.WriteString("  " + stDim.Render(strings.Join(bits, "   ")) + "\n\n")
		for _, r := range ar.Results {
			if r.Verdict == "seimbang" || r.Verdict == "" || r.Verdict == "tidak-ada-baseline" {
				continue
			}
			b.WriteString("  " + verdictTagStyle(r.Verdict) + " " +
				lipgloss.NewStyle().Bold(true).Foreground(cText).Render(r.Path) + "\n")
			for _, ln := range wrapN(r.Why, w-8) {
				b.WriteString("     " + stDim.Render(ln) + "\n")
			}
			b.WriteString("     " + lipgloss.NewStyle().Foreground(cInfo).Render(evidenceOf(r)) + "\n\n")
		}
	}
	return b.String()
}

func renderCakupan(m *TUIModel, w, _ int) string {
	c := m.cov
	var b strings.Builder
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cLow).
		Render(fmt.Sprintf("dianalisis (%d)", len(c.Analysed))) + "\n")
	for _, l := range c.Analysed {
		for _, ln := range wrapN("· "+l, w-6) {
			b.WriteString("    " + stDim.Render(ln) + "\n")
		}
	}
	b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Foreground(cMedium).
		Render(fmt.Sprintf("TIDAK diuji (%d)", len(c.NotTested))) + "\n")
	for _, l := range c.NotTested {
		for _, ln := range wrapN("· "+l, w-6) {
			b.WriteString("    " + lipgloss.NewStyle().Foreground(cMedium).Render(ln) + "\n")
		}
	}
	if len(c.Limits) > 0 {
		b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Foreground(cHigh).Render("batas") + "\n")
		for _, l := range c.Limits {
			for _, ln := range wrapN(l, w-8) {
				b.WriteString("    " + lipgloss.NewStyle().Foreground(cHigh).Render("· "+ln) + "\n")
			}
		}
	}
	return b.String()
}

// ── helper tampilan ────────────────────────────────────────────────────────

func severityTag(s Severity) string {
	switch s {
	case SevHigh:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#11111b")).Background(cHigh).Render(pad("HIGH", 5))
	case SevMedium:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#11111b")).Background(cMedium).Render(pad("MED", 5))
	case SevLow:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#11111b")).Background(cLow).Render(pad("LOW", 5))
	default:
		return lipgloss.NewStyle().Foreground(cInfo).Render(pad("INFO", 5))
	}
}

func verdictTagStyle(v string) string {
	switch v {
	case "anon-terbuka":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#11111b")).Background(cHigh).Render(pad("BUKA", 6))
	case "bola-dicurigai":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#11111b")).Background(cMedium).Render(pad("BOLA?", 6))
	default:
		return lipgloss.NewStyle().Foreground(cInfo).Render(pad("CEK", 6))
	}
}

// severityBar menggambar komposisi temuan sebagai bar proporsional.
//
// Panjang bar dibatasi. Tanpa batas, dua temuan akan mendapat bar sepanjang
// lebar terminal — secara proporsional "benar", tapi tidak ada artinya:
// bar sepanjang 116 karakter hanya supaya warna memenuhi layar. Batas atas
// menjaga bar tetap terbaca sebagai proporsi, bukan sebagai pengisi ruang.
func severityBar(counts map[Severity]int, total, w int) string {
	order := []Severity{SevHigh, SevMedium, SevLow, SevInfo}
	cols := map[Severity]lipgloss.Color{SevHigh: cHigh, SevMedium: cMedium, SevLow: cLow, SevInfo: cInfo}

	// Legend dibangun lebih dulu karena lebarnya harus diketahui sebelum
	// Decide sisa ruang untuk bar. Kalau dibalik, bar akan memakan seluruh
	// lebar dan mendorong legend melewati tepi terminal.
	type part struct {
		s Severity
		n int
	}
	var parts []part
	for _, s := range order {
		if n := counts[s]; n > 0 {
			parts = append(parts, part{s, n})
		}
	}
	if len(parts) == 0 {
		return ""
	}
	var legend strings.Builder
	for i, p := range parts {
		if i > 0 {
			legend.WriteString(stDim.Render("  "))
		}
		legend.WriteString(lipgloss.NewStyle().Foreground(cols[p.s]).
			Render(fmt.Sprintf("%d %s", p.n, p.s)))
	}

	const maxBar = 32
	barW := w - lipgloss.Width(legend.String()) - 2
	if barW > maxBar {
		barW = maxBar
	}
	if barW < 4 {
		// Tidak ada ruang untuk bar yang berarti. Legenda saja lebih
		// berguna daripada bar seadanya.
		return legend.String()
	}

	var bar strings.Builder
	used := 0
	for _, p := range parts {
		cells := p.n * barW / total
		if cells == 0 {
			cells = 1
		}
		if used+cells > barW {
			cells = barW - used
		}
		if cells <= 0 {
			continue
		}
		used += cells
		bar.WriteString(lipgloss.NewStyle().Foreground(cols[p.s]).Render(strings.Repeat("█", cells)))
	}
	// Bar dipadatkan ke lebar tetap supaya legend tidak bergeser saat
	// komposisi temuan berubah.
	return lipgloss.NewStyle().Width(barW).MaxWidth(barW).Render(bar.String()) +
		"  " + legend.String()
}

func stripScheme(u string) string {
	return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
}

func truncRight(s string, w int) string {
	r := []rune(s)
	if w <= 1 || len(r) <= w {
		return s
	}
	return string(r[:w-1]) + "…"
}

func wrapN(s string, w int) []string {
	if w < 10 {
		w = 10
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			continue
		}
		line := words[0]
		for _, wd := range words[1:] {
			if lipgloss.Width(line)+1+lipgloss.Width(wd) > w {
				out = append(out, line)
				line = wd
				continue
			}
			line += " " + wd
		}
		out = append(out, line)
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '.'); i > 0 {
		return s[:i+1]
	}
	return s
}

func fmtDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

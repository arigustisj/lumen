package lumen

import (
	"fmt"
	"strings"
)

// RenderDiff menggambar perbandingan dua scan untuk terminal.
//
// Urutan disengaja: peringatan cakupan dicetak lebih dulu. Kalau
// perbedaannya tidak sebanding, pembaca harus tahu itu sebelum melihat
// daftar "endpoint hilang" — kalau tidak, daftar itu akan dibaca sebagai
// hasil yang bermakna.
func RenderDiff(d DiffResults, st Style) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }

	w("")
	w("  " + st.Bold("PERUBAHAN SEJAK "+d.OldAt))
	w("")

	if !d.CoverageComparable {
		w("  " + st.Yellow("⚠ "+d.CoverageNote))
		w("  " + st.Dim("  daftar di bawah bisa mencerminkan hasil yang tidak lengkap, bukan perubahan nyata"))
		w("")
	}

	// Severity delta lebih dulu karena itu yang paling menentukan.
	var parts []string
	for _, s := range []Severity{SevHigh, SevMedium, SevLow, SevInfo} {
		dv := d.SeverityDelta[s]
		if dv == 0 {
			continue
		}
		sign := "+"
		if dv < 0 {
			sign = ""
		}
		style := func(t string) string { return st.Dim(t) }
		switch {
		case s == SevHigh && dv > 0:
			style = st.Red
		case s == SevHigh && dv < 0:
			style = st.Green
		case dv < 0:
			style = st.Green
		}
		parts = append(parts, style(fmt.Sprintf("%s%d %s", sign, dv, s)))
	}
	if len(parts) > 0 {
		w("  " + strings.Join(parts, "   "))
		w("")
	}

	if !d.HasChanges() {
		w("  " + st.Dim("tidak ada perubahan sejak scan sebelumnya"))
		w("")
		return b.String()
	}

	if len(d.NewFindings) > 0 {
		w("  " + st.Bold(sevStyled(st, SevHigh, "TEMUAN BARU")) + "  " + st.Dim(fmt.Sprintf("%d", len(d.NewFindings))))
		w("")
		for i, line := range limitList(st.Width-6, findingsToLines(d.NewFindings), maxItems(st)) {
			// Baris pertama tiap temuan memakai warna severity-nya.
			if i == 0 || isFirstLineOf(i, findingsToLines(d.NewFindings), st.Width-6, maxItems(st)) {
				w("    " + st.Red("▲") + " " + line)
			} else {
				w("      " + st.Dim(line))
			}
		}
		w("")
	}

	if len(d.ResolvedFindings) > 0 {
		label := "TEMUAN HILANG"
		if !d.CoverageComparable {
			// Ini bukan perbaikan. Menamadanya "hilang" saja sudah
			// cukup menyesatkan.
			label = "TEMUAN TIDAK MUNCUL LAGI"
		}
		w("  " + st.Bold(sevStyled(st, SevLow, label)) + "  " + st.Dim(fmt.Sprintf("%d", len(d.ResolvedFindings))))
		w("")
		for _, f := range limitList(st.Width-6, findingsToLines(d.ResolvedFindings), maxItems(st)) {
			w("    " + st.Dim("· ") + st.Dim(f))
		}
		w("")
	}

	if len(d.NewEndpoints) > 0 {
		w("  " + st.Bold("ENDPOINT BARU") + "  " + st.Dim(fmt.Sprintf("%d", len(d.NewEndpoints))))
		w("")
		for _, e := range limitList(st.Width-6, d.NewEndpoints, maxItems(st)) {
			w("    " + st.Dim("+ ") + e)
		}
		if n := len(d.NewEndpoints) - maxItems(st); n > 0 {
			w("    " + st.Dim(fmt.Sprintf("  +%d lainnya", n)))
		}
		w("")
	}

	if len(d.RemovedEndpoints) > 0 {
		label := "ENDPOINT HILANG"
		if !d.CoverageComparable {
			label = "ENDPOINT TIDAK TERLIHAT"
		}
		w("  " + st.Bold(sevStyled(st, SevLow, label)) + "  " + st.Dim(fmt.Sprintf("%d", len(d.RemovedEndpoints))))
		w("")
		for _, e := range limitList(st.Width-6, d.RemovedEndpoints, maxItems(st)) {
			w("    " + st.Dim("- ") + st.Dim(e))
		}
		if n := len(d.RemovedEndpoints) - maxItems(st); n > 0 {
			w("    " + st.Dim(fmt.Sprintf("  -%d lainnya", n)))
		}
		w("")
	}

	w("  " + st.Dim(fmt.Sprintf("%d endpoint tetap sama, %d temuan tidak berubah", d.KeptEndpoints, d.KeptFindings)))
	w("")
	return b.String()
}

// findingsToLines memformat temuan untuk daftar pendek.
func findingsToLines(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		s := f.Title
		if s == "" {
			s = firstLineOf(f.Detail)
		}
		out = append(out, s)
	}
	return out
}

// maxItems membatasi item per daftar supaya layar tidak meluber.
func maxItems(st Style) int {
	if st.Width < 50 {
		return 4
	}
	return 8
}

func limitList(width int, items []string, max int) []string {
	var out []string
	for i, s := range items {
		if i >= max {
			break
		}
		out = append(out, wrapN(s, width)...)
	}
	return out
}

// sevStyled memberi warna pada label sesuai tingkatnya.
func sevStyled(st Style, sev Severity, label string) string {
	switch sev {
	case SevHigh:
		return st.Red(label)
	case SevMedium:
		return st.Yellow(label)
	default:
		return st.Gray(label)
	}
}

// isFirstLineOf menandai baris yang memulai sebuah item setelah di-wrap.
func isFirstLineOf(i int, items []string, width, max int) bool {
	seen := 0
	for _, it := range items {
		if seen >= max {
			return false
		}
		if seen == i {
			return true
		}
		seen += len(wrapN(it, width))
		if seen > i {
			return false
		}
	}
	return false
}

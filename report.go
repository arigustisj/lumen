package lumen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Write menyimpan laporan JSON dengan permission ketat.
func Write(path string, r Report) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// 0600: laporan bisa memuat path internal, nama parameter, dan potongan
	// kredensial. Jangan sampai world-readable.
	return os.WriteFile(path, b, 0o600)
}

// Render menyusun tampilan terminal dari laporan.
//
// Hanya temuan medium ke atas yang ditampilkan penuh. Header keamanan yang
// hilang di setiap halaman menghasilkan puluhan baris low/info yang
// menenggelamkan yang penting — dan output yang tidak dibaca sama sekali
// setara dengan output yang tidak ada.
func Render(r Report, s Style, cands []Candidate, cov Coverage) string {
	var b strings.Builder
	g := s.Glyph

	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	// ── header ───────────────────────────────────────────────────────────
	b.WriteString("\n")
	// Header: nama + versi di kiri, target di kanan baris yang sama kalau
	// cukup lebar. Di layar sempit target pindah ke bawah supaya tidak
	// menimpa nama.
	brand := s.Bold(s.Cyan(Name)) + s.Gray(" "+Version)
	brandW := len([]rune(brand)) + 4
	head := brand
	if targetLine := r.Target; len([]rune(brand))+len([]rune(targetLine))+6 <= s.Width {
		gap := s.Width - brandW - len([]rune(targetLine))
		head = brand + strings.Repeat(" ", maxInt(1, gap)) + s.Dim(targetLine)
	} else {
		head = brand + "\n  " + s.Dim(r.Target)
	}
	b.WriteString("\n  " + head + "\n")
	// Baris identitas. Versi lama memakai deretan panah sebagai pemisah —
	// dekoratif tanpa informasi, dan di terminal sempit jadi deretan
	// yang membingungkan. Sekarang isinya justru berguna: apa tool ini dan
	// siapa yang membuatnya.
	ident := Tagline + "  " + g.Arrow + "  by " + Author
	if pad := s.Width - 4 - len([]rune(ident)); pad > 0 {
		ident += strings.Repeat(" ", pad)
	}
	b.WriteString("  " + s.Gray(ident) + "\n\n")

	// Meta ditulis per-item, bukan string gabungan yang lalu di-wrap.
	// Kalau digabung dulu, pemenggalan jatuh di tengah frasa — "halaman 1 →"
	// terpotong dari "bundle 1" yang menyusulnya.
	elapsed := time.Duration(r.DurationMS) * time.Millisecond
	meta := []string{
		s.Dim("durasi") + " " + s.Bold(elapsed.Round(time.Millisecond).String()),
		s.Dim("halaman") + " " + s.Bold(fmt.Sprint(len(r.Pages))),
		s.Dim("bundle") + " " + s.Bold(fmt.Sprint(r.Stats["bundle"])),
		s.Dim("endpoint") + " " + s.Bold(fmt.Sprint(len(r.Endpoints))),
	}
	line, indent := "", "  "
	for _, m := range meta {
		// +3: dua spasi + panah + dua spacing
		if line != "" && len([]rune(line))+len([]rune(m))+3 > s.Width-4 {
			b.WriteString(indent + line + "\n")
			line, indent = m, "      "
			continue
		}
		if line != "" {
			line += s.Dim("  " + g.Arrow + "  ")
		}
		line += m
	}
	if line != "" {
		b.WriteString(indent + line + "\n")
	}
	b.WriteString("\n")

	// ── komposisi temuan ──────────────────────────────────────────────────
	parts := []Part{
		{Label: "high", N: counts[SevHigh], Colour: s.Red},
		{Label: "medium", N: counts[SevMedium], Colour: s.Yellow},
		{Label: "low", N: counts[SevLow], Colour: s.Blue},
		{Label: "info", N: counts[SevInfo], Colour: s.Gray},
	}
	// Bar selebar sisa ruang:
	// Ketidakseimbangan: info biasanya 10-50x lebih banyak dari high, jadi
	// high habis di 1-2 karakter dan bar-nya tidak informatif sama sekali.
	// high/medium dipatok minimal 2 kolom supaya selalu kelihatan.
	barW := s.Width - 4 - 34
	if barW > 30 {
		barW = 30
	}
	if barW < 8 {
		barW = 8
	}
	b.WriteString("  " + s.Bar2(parts, barW) + "\n")
	var legend []string
	for _, p := range parts {
		legend = append(legend, fmt.Sprintf("%s %d", p.Colour(p.Label), p.N))
	}
	b.WriteString("  " + s.Gray(strings.Join(legend, "   ")) + "\n")

	// Guard scope: justru kabar baik kalau ada yang ditolak — artinya batasan
	// benar-benar bekerja, bukan tidak pernah diuji.
	if n := len(r.ScopeDenied); n > 0 {
		b.WriteString("  " + s.Green(g.Dot) +
			s.Dim(fmt.Sprintf(" %d host di luar scope ditolak — guard bekerja", n)) + "\n")
	}
	b.WriteString("\n")

	// ── temuan serius ─────────────────────────────────────────────────────
	var serious []Finding
	for _, f := range r.Findings {
		if f.Severity == SevHigh || f.Severity == SevMedium {
			serious = append(serious, f)
		}
	}
	if len(serious) > 0 {
		b.WriteString("  " + s.Bold("PERLU DILIHAT") + s.Dim("   high + medium") + "\n")
		b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
		for _, f := range serious {
			tag := s.Red("high")
			if f.Severity == SevMedium {
				tag = s.Yellow("med ")
			}
			head := tag + "  " + s.Bold(f.Kind) + "  " + f.Detail
			for i, ln := range s.Wrap(head, s.Width-4) {
				if i == 0 {
					b.WriteString("  " + ln + "\n")
				} else {
					b.WriteString("     " + ln + "\n")
				}
			}
			for _, ln := range s.Wrap("↳ "+f.Where, s.Width-6) {
				b.WriteString("     " + s.Dim(ln) + "\n")
			}
			b.WriteString("\n")
		}
	}

	// ── path dari bundle ──────────────────────────────────────────────────
	var flagged []Endpoint
	for _, e := range r.Endpoints {
		if len(e.Flags) > 0 && e.Origin == OriginJS {
			flagged = append(flagged, e)
		}
	}
	if len(flagged) > 0 {
		sort.Slice(flagged, func(i, j int) bool { return flagged[i].Path < flagged[j].Path })
		b.WriteString("  " + s.Bold("PATH DARI JS BUNDLE") +
			s.Dim(fmt.Sprintf("   %d — tidak ada di HTML, hanya di bundle", len(flagged))) + "\n")
		b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
		for _, e := range flagged {
			// Path adalah informasi utama. Di layar sempit, flag disembunyikan
			// lebih dulu — memotong path berarti menghilangkan informasi,
			// sementara flag masih bisa dibaca dari file JSON.
			method := s.Cyan(s.Pad(s.Truncate(e.Method, 6), 6))
			showFlag := s.Width >= 72
			room := s.Width - 11
			if showFlag {
				room -= 22
			}
			if room < 16 {
				room = 16
			}
			var line string
			if n := room - len([]rune(e.Path)); n > 0 {
				line = method + " " + e.Path + strings.Repeat(" ", n)
			} else {
				line = method + " " + s.Truncate(e.Path, room)
			}
			if showFlag {
				line += "  " + s.Dim(s.Truncate(strings.Join(e.Flags, " "), 20))
			}
			b.WriteString("  " + line + "\n")
		}
		b.WriteString("\n")
	}

	// ── kredensial ───────────────────────────────────────────────────────
	var secrets []Finding
	for _, f := range r.Findings {
		if f.Kind == "secret-di-bundle" {
			secrets = append(secrets, f)
		}
	}
	if len(secrets) > 0 {
		b.WriteString("  " + s.Bold(s.Red("KREDENSIAL DI BUNDLE")) + s.Dim("   nilai disamarkan") + "\n")
		b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
		for _, f := range secrets {
			for i, ln := range s.Wrap(f.Detail, s.Width-4) {
				if i == 0 {
					b.WriteString("  " + s.Red(g.Dot) + " " + ln + "\n")
				} else {
					b.WriteString("    " + ln + "\n")
				}
			}
			b.WriteString("    " + s.Dim("↳ "+f.Where) + "\n")
		}
		b.WriteString("\n")
	}

	// ── kandidat OWASP ────────────────────────────────────────────────────
	if len(cands) > 0 {
		byCat := map[string]int{}
		for _, c := range cands {
			byCat[c.Category]++
		}
		b.WriteString("  " + s.Bold("KANDIDAT OWASP") +
			s.Dim(fmt.Sprintf("   %d kandidat dari sinyal statis — belum terbukti", len(cands))) + "\n")
		b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
		for _, id := range sortedKeys(byCat) {
			cat, _ := categoryByID(id)
			h, m, lo := candsByConf(cands, id)
			mark := s.Gray(strconv.Itoa(byCat[id]))
			if h > 0 {
				mark = s.Red(strconv.Itoa(byCat[id]))
			} else if m > 0 {
				mark = s.Yellow(strconv.Itoa(byCat[id]))
			}
			_ = lo
			b.WriteString("  " + mark + "  " + s.Bold(cat.ID) + "  " + cat.Title +
				s.Dim("  ["+strings.Join(cat.CWE, ", ")+"]") + "\n")
		}
		b.WriteString("  " + s.Dim("  detail, langkah verifikasi, dan perbaikan ada di file JSON") + "\n\n")
	}

	// ── cakupan ───────────────────────────────────────────────────────────
	// Bagian ini yang membuat "tidak ada temuan" tidak disalahartikan sebagai
	// "aman". Tanpa ini, laporan kosong terlihat seperti hasil bersih.
	b.WriteString("  " + s.Bold("CAKUPAN") + s.Dim("   apa yang dianalisis, dan apa yang TIDAK") + "\n")
	b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
	for _, l := range cov.Analysed {
		b.WriteString("  " + s.Green(g.Dot) + " " + s.Dim("dianalisis   "+l) + "\n")
	}
	for _, l := range cov.NotTested {
		b.WriteString("  " + s.Yellow(g.Dot) + " " + s.Dim("TIDAK diuji  "+l) + "\n")
	}
	for _, l := range cov.Limits {
		for i, ln := range s.Wrap(l, s.Width-8) {
			if i == 0 {
				b.WriteString("  " + s.Red(g.Dot) + " " + s.Dim("batas        "+ln) + "\n")
			} else {
				b.WriteString("              " + s.Dim(ln) + "\n")
			}
		}
	}
	b.WriteString("\n")

	b.WriteString("  " + s.Gray(strings.Repeat(g.H, s.Width-4)) + "\n")
	b.WriteString("  " + s.Dim(r.GeneratedAt.Local().Format("2006-01-02 15:04:05 MST")) +
		"   " + s.Dim(s.Glyph.Arrow) + "   " + s.Gray(Tagline+" by "+Author) + "\n")
	return b.String()
}

// Footer menambahkan lokasi file output di akhir.
func candsByConf(cands []Candidate, id string) (high, med, low int) {
	for _, c := range cands {
		if c.Category != id {
			continue
		}
		switch c.Confidence {
		case "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}
	return
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func Footer(jsonPath, textPath string, s Style, sarifPath string, withSarif bool) string {
	var b strings.Builder
	b.WriteString("\n  " + s.Green(s.Glyph.Dot) + " " + s.Dim("json   ") + jsonPath + "\n")
	b.WriteString("  " + s.Green(s.Glyph.Dot) + " " + s.Dim("teks   ") + textPath + "\n")
	if withSarif {
		b.WriteString("  " + s.Green(s.Glyph.Dot) + " " + s.Dim("sarif  ") + sarifPath + "\n")
	}
	return b.String()
}

// SaveReport menulis JSON dan ringkasan teks ke disk.
//
// Teks yang disimpan SELALU tanpa escape warna: file ini dibaca manusia dan
// mungkin di-grep, dan karakter ANSI di dalam file cuma jadi sampah.
func SaveReport(jsonPath, textPath string, r Report, s Style, cands []Candidate, cov Coverage) error {
	if err := Write(jsonPath, r); err != nil {
		return err
	}
	if textPath == "" {
		return nil
	}
	if dir := filepath.Dir(textPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	plain := Plain(s.Unicode)
	plain.Width = 100
	return os.WriteFile(textPath, []byte(Render(r, plain, cands, cov)), 0o600)
}

// BySeverity mengurutkan temuan dari yang paling serius.
func BySeverity(fs []Finding) []Finding {
	out := make([]Finding, len(fs))
	copy(out, fs)
	rank := map[Severity]int{
		SevHigh: 0, SevMedium: 1, SevLow: 2, SevInfo: 3,
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

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
func Render(r Report, s Style, cands []Candidate, cov Coverage, compact bool, authz []AuthzReport) string {
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
	// Header harus langsung berisi informasi, bukan hiasan.
	// Di layar sempit, baris tagline dipindah ke footer: menambah satu
	// baris penuh di atas sebelum konten dimulai terasa boros, dan itu
	// itu yang bikin output "kepanjangan" di HP.
	// Tingkat bukti ditulis paling dekat dengan header. Placement-nya bukan
	// urusan estetika: ini yang paling sering salah dibaca pembaca. "0 temuan"
	// tanpa keterangan akan disimpulkan "aman", padahal bisa berarti tidak
	// sempat diperiksa.
	proof := BuildProof(&r)
	head2 := fmt.Sprintf("%s   %s", s.Dim("bukti"), proofLine(proof, s))
	b.WriteString("  " + head2 + "\n")
	b.WriteString("\n")

	brand := s.Bold(s.Cyan(Name)) + s.Gray(" "+Version)
	head := brand
	if t := strings.TrimPrefix(r.Target, "https://"); len([]rune(brand))+len([]rune(t))+3 <= s.Width {
		gap := s.Width - len([]rune(brand)) - len([]rune(t)) - 2
		head = brand + strings.Repeat(" ", maxInt(1, gap)) + s.Dim(s.Truncate(t, s.Width-len([]rune(brand))-2))
	}
	b.WriteString("  " + head + "\n")
	if !compact {
		b.WriteString("  " + s.Gray(Tagline+"  "+g.Arrow+"  by "+Author) + "\n")
	}
	b.WriteString("\n")

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
	// Di mode padat, meta dipisah titik saja (bukan panah) supaya muat satu
	// baris. Panah enak dibaca di terminal lebar, tapi di 56 kolom justru
	// ia yang memaksa baris jadi dua.
	sepStr := s.Dim("  " + g.Arrow + "  ")
	if compact {
		sepStr = s.Dim(" · ")
	}

	line, indent := "", "  "
	for _, m := range meta {
		if line != "" && len([]rune(line))+len([]rune(m))+len([]rune(sepStr)) > s.Width-4 {
			b.WriteString(indent + line + "\n")
			line, indent = m, "      "
			continue
		}
		if line != "" {
			line += sepStr
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
	var legend []string
	for _, p := range parts {
		legend = append(legend, fmt.Sprintf("%s %d", p.Colour(p.Label), p.N))
	}
	// Legend dan bar digabung kalau bar-nya pendek, supaya hemat satu baris.
	// Di HP itu perbedaan nyata: satu baris = satu layar fewer di-scroll.
	legendStr := strings.Join(legend, " ")
	if barW+len([]rune(legendStr))+3 <= s.Width-4 {
		b.WriteString("  " + s.Bar2(parts, barW) + "  " + legendStr + "\n")
	} else {
		b.WriteString("  " + s.Bar2(parts, barW) + "\n")
		b.WriteString("  " + legendStr + "\n")
	}

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
		// Di layar HP, daftar 40 temuan itu tidak pernah dibaca sampai habis —
		// jadi tampilkan yang paling penting, lalu sebut jumlahnya. Di mode
		// normal tidak ada batas: kalau lu sedang di depan laptop, lu memang
		// mau lihat semuanya.
		shownSerious := serious
		if compact && len(shownSerious) > 4 {
			shownSerious = shownSerious[:4]
		}
		for _, f := range shownSerious {
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
		if n := len(serious) - len(shownSerious); n > 0 {
			b.WriteString("  " + s.Yellow(fmt.Sprintf("  ... %d temuan lain — lihat file JSON", n)) + "\n\n")
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
		shown := flagged
		if compact && len(shown) > 10 {
			shown = shown[:10]
		}
		for _, e := range shown {
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
			// Padding hanya berguna kalau ada kolom lanjutan (flag). Kalau flag
			// disembunyikan, menambahkan spasi hanya menghasilkan baris dengan
			// ekor whitespace yang tidak terlihat tapi tetap ada di file teks.
			var line string
			if showFlag {
				if n := room - len([]rune(e.Path)); n > 0 {
					line = method + " " + e.Path + strings.Repeat(" ", n)
				} else {
					line = method + " " + s.Truncate(e.Path, room)
				}
			} else {
				line = method + " " + s.Truncate(e.Path, room)
			}
			if showFlag {
				line += "  " + s.Dim(s.Truncate(strings.Join(e.Flags, " "), 20))
			}
			b.WriteString("  " + line + "\n")
		}
		if n := len(flagged) - len(shown); n > 0 {
			b.WriteString("  " + s.Yellow(fmt.Sprintf("  ... %d path lain — buka out/*.json, atau jalankan di terminal lebar", n)) + "\n")
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
	// Cakupan adalah bagian yang WAJIB ada — tanpa itu laporan kosong terlihat
	// sama dengan laporan bersih. Jadi di mode padat pun tidak dihapus; yang
	// dipangkas cuma baris pertamanya, karena "[[N] item selengkapnya ada di
	// JSON]" sudah cukup memberi tahu tanpa memakan layar.
	analysed, notTested := cov.Analysed, cov.NotTested
	if compact {
		if len(analysed) > 2 {
			analysed = analysed[:2]
		}
		if len(notTested) > 3 {
			notTested = notTested[:3]
		}
	}
	for _, l := range analysed {
		b.WriteString("  " + s.Green(g.Dot) + " " + s.Dim("dianalisis  "+l) + "\n")
	}
	for _, l := range notTested {
		b.WriteString("  " + s.Yellow(g.Dot) + " " + s.Dim("TIDAK diuji "+l) + "\n")
	}
	if compact && (len(cov.Analysed) > len(analysed) || len(cov.NotTested) > len(notTested)) {
		b.WriteString("  " + s.Dim(fmt.Sprintf("  ... daftar lengkap di file JSON (%d dianalisis, %d tidak diuji)",
			len(cov.Analysed), len(cov.NotTested))) + "\n")
	}
	// Batas hanya ditampilkan ringkas di mode padat; versi lengkap tetap ada
	// di JSON dan di file teks.
	limits := cov.Limits
	if compact {
		limits = limits[:minInt(2, len(limits))]
	}
	for _, l := range limits {
		for i, ln := range s.Wrap(l, s.Width-10) {
			if i == 0 {
				b.WriteString("  " + s.Red(g.Dot) + " " + s.Dim("batas       "+ln) + "\n")
			} else {
				b.WriteString("             " + s.Dim(ln) + "\n")
			}
		}
	}
	if compact && len(cov.Limits) > len(limits) {
		b.WriteString("  " + s.Dim(fmt.Sprintf("  ... %d batas lain — lihat file JSON", len(cov.Limits)-len(limits))) + "\n")
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
func SaveReport(jsonPath, textPath string, r Report, s Style, cands []Candidate, cov Coverage, compact bool, authz []AuthzReport) error {
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
	return os.WriteFile(textPath, []byte(Render(r, plain, cands, cov, compact, authz)), 0o600)
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

// evidenceOf merangkum bukti per perspektif untuk satu endpoint.
func evidenceOf(r AuthzResult) string {
	var parts []string
	for _, k := range sortedViewKeys(r.Views) {
		v := r.Views[k]
		if v.Error != "" {
			parts = append(parts, k+"="+truncMid(v.Error, 28))
			continue
		}
		if v.Redirect != "" {
			parts = append(parts, fmt.Sprintf("%s=%d→%s", k, v.Status, truncMid(v.Redirect, 24)))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d/%dB", k, v.Status, v.Length))
	}
	return strings.Join(parts, "  ")
}

func verdictLabel(v string) string {
	switch v {
	case "anon-terbuka":
		return "ANON TERBUKA"
	case "bola-dicurigai":
		return "BOLA?"
	case "auth-tidak-aktif":
		return "AUTH OFF"
	default:
		return v
	}
}

func verdictColour(v string, s Style) func(string) string {
	switch v {
	case "anon-terbuka":
		return s.Red
	case "bola-dicurigai":
		return s.Yellow
	default:
		return s.Dim
	}
}

func truncMid(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	half := (n - 1) / 2
	return string(r[:half]) + "…" + string(r[len(r)-half:])
}

// proofLine merender tingkat bukti dengan warna yang berbeda per tingkat.
//
// Warnanya bukan hiasan: "terbukti" dan "kandidat" harus terpisah secara
// visual, karena keduanya sering muncul berdampingan dalam laporan yang sama
// dan tidak boleh dibaca sebagai kategori yang sama.
func proofLine(p Proof, s Style) string {
	var parts []string
	if p.Proven > 0 {
		parts = append(parts, s.Red(fmt.Sprintf("%d terbukti", p.Proven)))
	} else {
		parts = append(parts, s.Dim("0 terbukti"))
	}
	parts = append(parts, s.Yellow(fmt.Sprintf("%d kandidat", p.Candidate)))
	if p.Untested > 0 {
		parts = append(parts, s.Dim(fmt.Sprintf("%d tidak diuji", p.Untested)))
	}
	return strings.Join(parts, "  ")
}

package lumen

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Laporan Markdown.
//
// Format ini dibuat untuk dibaca mesin lebih dulu, manusia belakangan.
//
// Prinsipnya:
//   - Satu temuan satu bagian dengan judul yang_ISI, bukan ID aturan.
//   - Setiap temuan punya bukti dan langkah verifikasi yang bisa dijalankan.
//   - Bagian "tidak diuji" wajib ada. Laporan yang tidak menyebutkan batasnya
//     encourage kesimpulan yang tidak didukung bukti.
//   - Tidak ada kalimat pengantar, tidak ada penutup. Markdown untuk agent
//     tidak butuh sapaan.

const mdSchema = "lumen/1"

// WriteMarkdown menulis laporan .md untuk agent AI.
func WriteMarkdown(path string, rep *Report, cands []Candidate, cov Coverage, run Run) error {
	var b strings.Builder
	writeMarkdown(&b, rep, cands, cov, run)
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func writeMarkdown(b *strings.Builder, rep *Report, cands []Candidate, cov Coverage, run Run) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }

	// ── Ringkasan ──────────────────────────────────────────────────────────
	// Ditulis lebih dulu dan satu paragraf, supaya pembaca bisa memutuskan
	// perlu membaca seluruh dokumen atau tidak tanpa menggulir.
	verdict := "TIDAK ADA TEMUAN"
	if n := countSeverity(rep.Findings, SevHigh); n > 0 {
		verdict = fmt.Sprintf("PERLU TINDAKAN — %d temuan high", n)
	} else if n := countSeverity(rep.Findings, SevMedium); n > 0 {
		verdict = fmt.Sprintf("PERIKSA — %d temuan medium", n)
	} else if len(rep.Findings) > 0 {
		verdict = fmt.Sprintf("RESIKO RENDAH — %d temuan low/info", len(rep.Findings))
	}

	w("---")
	w("schema: %s", mdSchema)
	w("tool: %s %s", Name, Version)
	w("target: %s", rep.Target)
	w("scanned_at: %s", rep.GeneratedAt.UTC().Format(time.RFC3339))
	w("verdict: %s", verdict)
	w("---")
	w("")
	w("# %s — %s", Name, rep.Target)
	w("")
	w("**%s.** %d halaman, %d endpoint, %d temuan (%s), %d kandidat OWASP. Dipindai dalam %s.",
		verdict, len(rep.Pages), len(rep.Endpoints), len(rep.Findings), severityBreakdown(rep.Findings), len(cands), fmtDuration(rep.DurationMS))
	w("")

	if rep.RootError != "" {
		w("> **SCAN GAGAL.** Halaman awal tidak bisa diambil: `%s`", rep.RootError)
		w("> Hasil di bawah tidak boleh dianggap \"situs ini bersih\" — pemetaan belum selesai.")
		w("")
	}
	if rep.DNSNote != "" {
		w("> **DNS.** %s", rep.DNSNote)
		w("")
	}

	// ── Temuan ─────────────────────────────────────────────────────────────
	high := filterSeverity(rep.Findings, SevHigh)
	medium := filterSeverity(rep.Findings, SevMedium)
	rest := otherFindings(rep.Findings)

	if len(high) > 0 {
		w("## Temuan yang perlu diperbaiki")
		w("")
		for i, f := range high {
			writeFinding(b, i+1, f)
		}
	}
	if len(medium) > 0 {
		w("## Temuan yang perlu diperiksa")
		w("")
		for i, f := range medium {
			writeFinding(b, i+1, f)
		}
	}
	if len(rest) > 0 {
		w("## Temuan lain")
		w("")
		for i, f := range rest {
			writeFinding(b, i+1, f)
		}
	}
	if len(rep.Findings) == 0 {
		w("## Temuan")
		w("")
		w("Tidak ada temuan pada pemeriksaan ini. **Ini bukan berarti aman** — baca bagian Cakupan.")
		w("")
	}

	// ── Kandidat OWASP ─────────────────────────────────────────────────────
	if groups := GroupCandidates(cands); len(groups) > 0 {
		total := len(cands)
		w("## Kandidat OWASP")
		w("")
		w("%d kandidat dari %d aturan berbeda. Semuanya sinyal statis — belum ada yang terbukti.", total, len(groups))
		w("")
		for _, g := range groups {
			w("### %s %s — %d endpoint", g.Category, g.Title, g.Count)
			w("")
			w("- **confidence**: %s", g.Confidence)
			if len(g.CWE) > 0 {
				w("- **CWE**: %s", strings.Join(g.CWE, ", "))
			}
			w("")
			w("**Sinyal.** %s", g.Signal)
			w("")
			w("**Cara memverifikasi.** %s", g.Verify)
			w("")
			if len(g.Examples) > 0 {
				w("**Endpoint yang memicunya** (%d):", len(g.Examples))
				for _, e := range g.Examples {
					w("- `%s`", e)
				}
				w("")
			}
			if g.Remediate != "" {
				w("**Perbaikan.** %s", g.Remediate)
				w("")
			}
		}
	}

	// ── Authz ──────────────────────────────────────────────────────────────
	if rep.Authz != nil {
		writeAuthzSection(b, *rep.Authz)
	}

	// ── Endpoint ───────────────────────────────────────────────────────────
	if len(rep.Endpoints) > 0 {
		w("## Endpoint")
		w("")
		fromJS := make([]Endpoint, 0, len(rep.Endpoints))
		for _, e := range rep.Endpoints {
			if e.Origin == OriginJS {
				fromJS = append(fromJS, e)
			}
		}
		w("Total %d endpoint. %d di antaranya tidak muncul di HTML dan hanya ditemukan di JavaScript bundle.",
			len(rep.Endpoints), len(fromJS))
		w("")
		if len(fromJS) > 0 {
			w("### Hanya di JS bundle")
			w("")
			w("| method | path | status |")
			w("|---|---|---|")
			for _, e := range fromJS {
				st := "-"
				if e.Status > 0 {
					st = fmt.Sprint(e.Status)
				}
				w("| %s | `%s` | %s |", e.Method, e.Path, st)
			}
			w("")
		}
	}

	// ── Cakupan ────────────────────────────────────────────────────────────
	// Bagian yang paling sering dihapus dari laporan, dan paling penting.
	// Tanpa ini, "tidak menemukan apa-apa" dan "tidak sempat memeriksa"
	// menjadi kalimat yang sama.
	w("## Cakupan")
	w("")
	w("### Yang dianalisis")
	for _, l := range cov.Analysed {
		w("- %s", l)
	}
	w("")
	w("### Yang TIDAK dianalisis")
	for _, l := range cov.NotTested {
		w("- %s", l)
	}
	w("")
	if len(cov.Limits) > 0 {
		w("### Batas alat ini")
		for _, l := range cov.Limits {
			w("- %s", l)
		}
		w("")
	}
	if len(rep.ScopeDenied) > 0 {
		w("### Ditolak karena di luar scope")
		for _, d := range rep.ScopeDenied {
			w("- `%s`", d)
		}
		w("")
	}

	if len(run.Target) > 0 {
		w("---")
		w("run: %s  ·  file: %s", run.At.UTC().Format(time.RFC3339), run.File)
	}
}

func writeFinding(b *strings.Builder, n int, f Finding) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }
	// Fallback untuk temuan lama yang belum punya Title: pakai baris pertama
	// Detail. Judul hasil fallback bisa panjang, tapi lebih baik daripada
	// bagian tanpa judul sama sekali.
	title := f.Title
	body := f.Detail
	if title == "" {
		title = firstLineOf(f.Detail)
		body = strings.TrimSpace(strings.TrimPrefix(f.Detail, title))
	}
	w("### %d. %s", n, title)
	w("")
	w("- **severity**: %s", f.Severity)
	w("- **kind**: %s", f.Kind)
	w("- **lokasi**: `%s`", f.Where)
	w("")
	if body == "" {
		body = title
	}
	w("%s", body)
	w("")
}

func writeAuthzSection(b *strings.Builder, ar AuthzReport) {
	w := func(format string, a ...any) { fmt.Fprintf(b, format+"\n", a...) }

	w("## Otorisasi diferensial")
	w("")
	w("Endpoint diuji dengan GET identik dari beberapa perspektif. %d diuji, %d dilewati (non-GET atau placeholder).",
		ar.Tested, ar.Skipped)
	w("")

	counts := map[string]int{}
	for _, r := range ar.Results {
		counts[r.Verdict]++
	}
	w("| vonis | jumlah |")
	w("|---|---|")
	for _, v := range []string{"anon-terbuka", "bola-dicurigai", "auth-tidak-aktif", "seimbang"} {
		if counts[v] > 0 {
			w("| %s | %d |", v, counts[v])
		}
	}
	w("")

	for _, r := range ar.Results {
		if r.Verdict == "seimbang" || r.Verdict == "" {
			continue
		}
		w("### %s — `%s`", r.Verdict, r.Path)
		w("")
		w("%s", r.Why)
		w("")
		w("| perspektif | status | ukuran |")
		w("|---|---|---|")
		for _, k := range sortedViewKeys(r.Views) {
			v := r.Views[k]
			if v.Error != "" {
				w("| %s | error | %s |", k, v.Error)
				continue
			}
			w("| %s | %d | %d B |", k, v.Status, v.Length)
		}
		w("")
		if f := FindingFromAuthz(r); f != nil {
			w("**Tindakan.** %s", f.Detail)
			w("")
		}
	}
}

func countSeverity(fs []Finding, s Severity) int {
	n := 0
	for _, f := range fs {
		if f.Severity == s {
			n++
		}
	}
	return n
}

func filterSeverity(fs []Finding, s Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity == s {
			out = append(out, f)
		}
	}
	return out
}

// otherFindings mengembalikan temuan selain high dan medium, diurutkan
// berdasarkan berat.
func otherFindings(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity != SevHigh && f.Severity != SevMedium {
			out = append(out, f)
		}
	}
	return out
}

func severityBreakdown(fs []Finding) string {
	var parts []string
	for _, s := range []Severity{SevHigh, SevMedium, SevLow, SevInfo} {
		if n := countSeverity(fs, s); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, ", ")
}

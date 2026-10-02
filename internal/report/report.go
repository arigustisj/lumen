// Package report merakit hasil crawl menjadi file JSON dan ringkasan terminal.
//
// Dua format dengan sengaja: JSON untuk agent/diff, teks untuk mata manusia.
// Sebagian besar temuan keamanan tidak pernah dibaca ulang sebagai JSON.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"lumen/internal/model"
)

// Write menyimpan laporan JSON dengan permission ketat.
func Write(path string, r model.Report) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	// 0600: laporan bisa memuat path internal, nama param, dan potongan
	// kredensial. Jangan sampai world-readable.
	return os.WriteFile(path, b, 0o600)
}

// Summary menulis ringkasan ke stdout.
//
// Hanya temuan medium ke atas yang ditampilkan di sini. Server yang Reported
// "Secure" yang missing security headers_none akanpz 40 baris spam low/info
// dan membuat yang penting tenggelam.
func Summary(r model.Report) string {
	var b strings.Builder

	fmt.Fprintf(&b, "target      : %s\n", r.Target)
	fmt.Fprintf(&b, "waktu       : %s\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "durasi      : %dms\n", r.DurationMS)
	fmt.Fprintf(&b, "halaman     : %d\n", len(r.Pages))
	fmt.Fprintf(&b, "bundle JS   : %d\n", r.Stats["bundle"])
	fmt.Fprintf(&b, "endpoint    : %d\n", len(r.Endpoints))
	if n := len(r.ScopeDenied); n > 0 {
		fmt.Fprintf(&b, "di luar scope: %d host DITOLAK (guard bekerja)\n", n)
	}
	b.WriteString("\n")

	counts := map[model.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, "temuan      : high %d | medium %d | low %d | info %d\n",
		counts[model.SevHigh], counts[model.SevMedium], counts[model.SevLow], counts[model.SevInfo])

	interesting := make([]model.Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Severity == model.SevHigh || f.Severity == model.SevMedium {
			interesting = append(interesting, f)
		}
	}
	if len(interesting) > 0 {
		b.WriteString("\n-- perlu dilihat manusia --\n")
		for _, f := range interesting {
			fmt.Fprintf(&b, "  [%-6s] %-18s %s\n    di: %s\n",
				f.Severity, f.Kind, f.Detail, f.Where)
		}
	}

	// Endpoint dari JS yang punya flag — bagian paling biasanyaBerguna.
	var flagged []model.Endpoint
	for _, e := range r.Endpoints {
		if len(e.Flags) > 0 && e.Origin == model.OriginJS {
			flagged = append(flagged, e)
		}
	}
	if len(flagged) > 0 {
		b.WriteString("\n-- endpoint dari JS yang perlu diuji manual --\n")
		for _, e := range flagged {
			fmt.Fprintf(&b, "  %-7s %-60s %v\n", e.Method, trunc(e.Path, 60), e.Flags)
		}
	}

	// Kredensial yang tertanam selalu dicetak penuh: ini yang paling sering
	// terbawa ke production tanpa disadari.
	var secrets []model.Finding
	for _, f := range r.Findings {
		if f.Kind == "secret-di-bundle" {
			secrets = append(secrets, f)
		}
	}
	if len(secrets) > 0 {
		b.WriteString("\n-- KREDENSIAL DI BUNDLE (rotasi kalau nyata) --\n")
		for _, f := range secrets {
			fmt.Fprintf(&b, "  %s\n    %s\n", f.Detail, f.Where)
		}
	}

	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// Save writes both JSON and a text summary next to it.
func Save(jsonPath, textPath string, r model.Report) error {
	if err := Write(jsonPath, r); err != nil {
		return err
	}
	sum := Summary(r)
	if textPath == "" {
		return nil
	}
	if dir := filepath.Dir(textPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(textPath, []byte(sum), 0o600)
}

// BySeverity mengurutkan temuan dari yang paling serius.
func BySeverity(fs []model.Finding) []model.Finding {
	out := make([]model.Finding, len(fs))
	copy(out, fs)
	rank := map[model.Severity]int{
		model.SevHigh: 0, model.SevMedium: 1, model.SevLow: 2, model.SevInfo: 3,
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

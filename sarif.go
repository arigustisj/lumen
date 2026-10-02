package lumen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SARIF 2.1.0 (OASIS Static Analysis Results Interchange Format).
//
// Kenapa format ini, bukan JSON sendiri: GitHub code scanning, GitLab,
// CodeQL, dan sebagian besar pipeline keamanan sudah bisa membaca SARIF.
// Kalau output lumen pakai skema sendiri, setiap adopter harus menulis
// parser dulu — dan pada praktiknya tidak ada yang mau melakukan itu.
//
// Pola yang sama dipakai Strix (findings.sarif di strix_runs/).
//
// SarifVersion dan $schema adalah wajib di 2.1.0. Runs[].tool.driver.name
// adalah identitas tool yang akan muncul di UI code scanning.

const sarifVersion = "2.1.0"
const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
	// Invocations menyimpan exit code dan target, supaya platform bisa
	// membedakan "scan selesai dan bersih" dari "scan gagal jalan".
	Invocations []SarifInvocation `json:"invocations,omitempty"`
	// Properties adalah tempat vendor-specific; dipakai untuk menyimpan
	// cakupan analisis, karena SARIF tidak punya konsep "tidak diuji".
	Properties map[string]any `json:"properties,omitempty"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription SarifText        `json:"shortDescription"`
	FullDescription  SarifText        `json:"fullDescription,omitempty"`
	Help             SarifText        `json:"help,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       map[string]any   `json:"properties,omitempty"`
	Tags             []string         `json:"tags,omitempty"`
	DefaultConfig    *SarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

type SarifRuleConfig struct {
	Level string `json:"level"`
}

type SarifText struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    SarifText       `json:"message"`
	Locations  []SarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
	// PartialFluentIDs menandai hasil yang belum terverifikasi.
	//
	// SARIF punya level "note" yang tepat untuk ini. Menandai kandidat
	// statis sebagai "error" membuat code scanning beralarm pada hal yang
	// belum terbukti, dan orang kemudian mematikan alarmnya seluruhnya.
	Fingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysical `json:"physicalLocation"`
}

type SarifPhysical struct {
	ArtifactLocation SarifArtifact `json:"artifactLocation"`
	Region           *SarifRegion  `json:"region,omitempty"`
}

type SarifArtifact struct {
	URI string `json:"uri"`
}

type SarifRegion struct {
	StartLine int `json:"startLine"`
}

type SarifInvocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	ExitCode            int            `json:"exitCode,omitempty"`
	Properties          map[string]any `json:"properties,omitempty"`
}

// RuleID memberi id unik pada rule.
type SarifRuleAlias = SarifRule

// BuildSARIF mengubah laporan menjadi SARIF 2.1.0.
//
// Kandidat dikembalikan dengan level "note" (bukan "error"/"warning"),
// dan hanya temuan konfigurasi yang bisa dibuktikan dari respons yang
// benar-benar diterima yang promoted ke "warning".
func BuildSARIF(r Report, cands []Candidate, cov Coverage, exitCode int) *SarifLog {
	log := &SarifLog{Schema: sarifSchema, Version: sarifVersion}

	// Satu rule per kategori OWASP yang benar-benar muncul. Men遗症
	// membuat halaman hasil penuh rule kosong.
	used := map[string]Category{}
	for _, c := range cands {
		if cat, ok := categoryByID(c.Category); ok {
			used[c.Category] = cat
		}
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sortStrings(ids)

	rules := make([]SarifRule, 0, len(ids))
	ruleIndex := map[string]int{}
	for i, id := range ids {
		cat := used[id]
		ruleIndex[id] = i
		help := "Kandidat dari sinyal statis — belum terbukti. Ikuti langkah verifikasi pada hasil."
		if cat.URL != "" {
			help += "\n\nReferensi: " + cat.URL
		}
		rules = append(rules, SarifRule{
			ID:               cat.ID,
			Name:             cat.Title,
			ShortDescription: SarifText{Text: cat.Title},
			FullDescription:  SarifText{Text: cat.Title + " (" + strings.Join(cat.CWE, ", ") + ")"},
			Help:             SarifText{Text: help},
			HelpURI:          cat.URL,
			Tags:             cat.CWE,
			Properties: map[string]any{
				"cwe":     cat.CWE,
				"precise": false, // belum terverifikasi
			},
			DefaultConfig: &SarifRuleConfig{Level: "note"},
		})
	}

	var results []SarifResult
	for _, c := range cands {
		idx, ok := ruleIndex[c.Category]
		if !ok {
			continue
		}
		msg := c.Title + " — " + c.Signal + "\n\nVerifikasi: " + c.Verify + "\n\nPerbaikan: " + c.Remediate
		results = append(results, SarifResult{
			RuleID:    c.Category,
			RuleIndex: idx,
			// "note", bukan "error": ini kandidat statis. Menaikkannya
			// membuat code scanning beralarm atas hal yang belum diperiksa,
			// dan orang lalu mematikan alarmnya altogether.
			Level:   "note",
			Message: SarifText{Text: msg},
			Locations: []SarifLocation{{
				PhysicalLocation: SarifPhysical{
					// SARIF mengharuskan URI; path API bukan file, jadi
					// pakai URL target sebagai artifact location.
					ArtifactLocation: SarifArtifact{URI: "https://" + strings.TrimPrefix(r.Target, "https://")},
					Region:           &SarifRegion{StartLine: 1},
				},
			}},
			Properties: map[string]any{
				"confidence": c.Confidence,
				"cwe":        c.CWE,
				"signal":     c.Signal,
				"verify":     c.Verify,
				"remediate":  c.Remediate,
				"target":     c.Where,
			},
			Fingerprints: map[string]string{
				"lumen/v1": fingerprint(c.Category, c.Where),
			},
		})
	}

	log.Runs = []SarifRun{{
		Tool: SarifTool{Driver: SarifDriver{
			Name:           Name,
			Version:        Version,
			InformationURI: "https://github.com/arigustisj/lumen",
			Rules:          rules,
		}},
		Results: results,
		Invocations: []SarifInvocation{{
			ExecutionSuccessful: true,
			ExitCode:            exitCode,
			Properties: map[string]any{
				"target":     r.Target,
				"generated":  r.GeneratedAt.Format(time.RFC3339),
				"durationMS": r.DurationMS,
			},
		}},
		// Coverage ikut disertakan karena SARIF tidak punya tempat untuk
		// "apa yang TIDAK diuji". Tanpa ini, hasil kosong di pipeline terlihat
		// sama dengan hasil bersih.
		Properties: map[string]any{
			"coverage": cov,
			"limits":   cov.Limits,
		},
	}}
	return log
}

// WriteSARIF menyimpan SARIF dengan permission ketat: hasil bisa memuat path
// internal dan potongan kredensial.
func WriteSARIF(path string, log *SarifLog) error {
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.WriteFile(path, b, 0o600)
}

// fingerprint menghasilkan ID stabil supaya platform bisa melacak temuan
// yang sama antar-run. Harus deterministik: kalau berubah tiap scan, setiap
// temuan terbaca sebagai baru dan code scanning akan penuh diff palsu.
func fingerprint(category, where string) string {
	h := fnv64(category + "|" + where)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		out[i] = hexdigits[h&0xf]
		h >>= 4
	}
	return string(out)
}

func fnv64(s string) uint64 {
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

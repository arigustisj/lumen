package lumen

import (
	"fmt"
	"sort"
)

// CandidateGroup menggabungkan semua kandidat yang jatuh ke aturan yang sama.
//
// Classify mengembalikan satu Candidate per endpoint yang cocok, supaya
// tidak ada informasi yang hilang. Untuk ditampilkan, itu salah bentuk:
// seratus endpoint dengan pola sama jadi seratus baris identik. Laporan
// 53 KB yang 40 KB-nya pengulangan tidak bisa dibaca agent maupun manusia.
//
// Aturan di-instance kalimat yang sama persis, jadi menggabungkan tidak
// kehilangan informasi apa pun.
type CandidateGroup struct {
	ID         string
	Category   string
	Title      string
	CWE        []string
	Confidence string
	Signal     string
	Verify     string
	Remediate  string
	Count      int
	Examples   []string
}

// GroupCandidates menggabungkan kandidat berdasarkan ID aturan.
func GroupCandidates(cands []Candidate) []CandidateGroup {
	idx := map[string]*CandidateGroup{}
	var order []string
	for _, c := range cands {
		g, ok := idx[c.ID]
		if !ok {
			g = &CandidateGroup{
				ID: c.ID, Category: c.Category, Title: c.Title,
				CWE: c.CWE, Confidence: c.Confidence,
				Signal: c.Signal, Verify: c.Verify, Remediate: c.Remediate,
			}
			idx[c.ID] = g
			order = append(order, c.ID)
		}
		g.Count++
		for _, e := range c.Examples {
			if !containsStr(g.Examples, e) {
				g.Examples = append(g.Examples, e)
			}
		}
	}
	out := make([]CandidateGroup, 0, len(order))
	for _, id := range order {
		g := idx[id]
		if g.Count == 0 {
			g.Count = 1
		}
		out = append(out, *g)
	}
	// Terbanyak dulu: baris paling atas adalah yang paling pekerjaan.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Category < out[j].Category
	})
	return out
}

// String meringkas satu kelompok untuk ditampilkan sebaris.
func (g CandidateGroup) String() string {
	return fmt.Sprintf("%s %s — %s (%d endpoint)", g.Category, g.Title, g.Confidence, g.Count)
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

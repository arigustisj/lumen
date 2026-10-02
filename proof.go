package lumen

import "fmt"

// Lapisan bukti.
//
// Cardinalitas utama tool ini: ia tidak pernah melaporkan sesuatu sebagai
// kerentanan kecuali ada respons nyata yang membuktikannya. Semua yang lain
// diberi label kandidat, dan yang tidak diperiksa diberi label eksplisit.
//
// Tiga tingkat ini tidak boleh dicampur. Laporan yang hanya punya dua tingkat
// — "temuan" dan "nihil" — membuat pembaca tidak bisa membedakan "aman"
// dari "tidak sempat dicek", dan itu sumber salah paham paling mahal di
// laporan keamanan.
const (
	// EvidenceProven berarti ada respons nyata yang membuktikan.
	EvidenceProven = "terbukti"
	// EvidenceCandidate berarti sinyal statis saja, belum ada konfirmasi.
	EvidenceCandidate = "kandidat"
	// EvidenceUntested berarti tidak diperiksa, jadi tidak ada yang bisa
	// disimpulkan — bukan berarti aman.
	EvidenceUntested = "tidak-diuji"
)

// Proof adalah ringkasan tingkat bukti untuk satu laporan.
type Proof struct {
	Proven int
	// Candidate menghitung kandidat OWASP, bukan temuan. Kandidat adalah
	// "periksa ini"; temuan adalah "ini terjadi".
	Candidate int
	// StrongCandidate hanya kandidat confidence tinggi.
	StrongCandidate int
	Untested        int
	Note            string
}

// BuildProof menyusun ringkasan tingkat bukti.
//
// Untested dihitung dari Endpoint yang tidak pernah dipanggil authz — bukan
// dari tebakan. Kalau ada 40 endpoint yang tidak diuji, menulis "0 temuan"
// tanpa menyebutkan itu adalah setengah kebohongan.
func BuildProof(rep *Report) Proof {
	p := Proof{}
	if rep == nil {
		return p
	}

	// Temuan yang punya respons nyata dihitung sebagai terbukti, bukan
	// hanya authz. "Header HSTS tidak ada" bukan dugaan — ada respons yang
	// diambil, dan headernya memang tidak ada di sana. Menghitungnya
	// sebagai kandidat akan merendahkan bukti yang sebenarnya ada.
	for _, f := range rep.Findings {
		switch EvidenceClass(f, rep) {
		case EvidenceProven:
			p.Proven++
		case EvidenceUntested:
			p.Untested++
		default:
			p.Candidate++
		}
	}

	if rep.Authz != nil {
		for _, r := range rep.Authz.Results {
			switch r.Verdict {
			case "anon-terbuka", "bola-dicurigai", "auth-tidak-aktif":
				p.Proven++
			case "shell-spa", "seimbang":
				// Bukan bukti bocor. "seimbang" juga bukan bukti aman —
				// datanya bisa memang publik.
			default:
				p.Candidate++
			}
		}
		p.Untested += rep.Authz.Skipped
	}

	// Kandidat OWASP dihitung terpisah dari temuan: itu kelompok yang
	// berbeda, bukan pengulangan. Satu endpoint bisa punya beberapa kandidat
	// sekaligus, jadi menjumlahkannya ke temuan akan mengacak angka.
	for _, c := range rep.Candidates {
		if c.Confidence == "low" {
			continue
		}
		p.Candidate++
		if c.Confidence == "high" {
			p.StrongCandidate++
		}
	}
	return p
}

// EvidenceClass mengembalikan tingkat bukti untuk sebuah temuan.
func EvidenceClass(f Finding, rep *Report) string {
	switch f.Kind {
	case "authz-anon-terbuka", "authz-bola-dicurigai", "authz-auth-tidak-aktif":
		return EvidenceProven
	case "header", "flag", "cors":
		// Header yang absen adalah fakta terukur, bukan dugaan: ada
		// respons, dan headernya memang tidak ada di sana.
		return EvidenceProven
	case "bundle", "tech", "kredensial":
		return EvidenceCandidate
	}
	if rep != nil && rep.RootError != "" {
		return EvidenceUntested
	}
	return EvidenceCandidate
}

// ProvenLine meringkas tingkat bukti dalam satu kalimat.
func (p Proof) ProvenLine() string {
	if p.Proven == 0 {
		return fmt.Sprintf("0 terbukti · %d kandidat · %d tidak diuji", p.Candidate, p.Untested)
	}
	return fmt.Sprintf("%d terbukti · %d kandidat · %d tidak diuji", p.Proven, p.Candidate, p.Untested)
}

package lumen

import (
	"fmt"
	"sort"
	"strings"
)

// Diff antar dua scan.
//
// Kegunaannya bukan cuma "apa yang berubah". Tanpa diff, riwayat cuma
// tumpukan laporan yang semuanya terlihat sama. Dengan diff, satu
// pertanyaan bisa dijawab langsung: sejak scan terakhir, apa yang berubah.
//
// Peringatan yang harus selalu ikut: endpoint yang hilang belum tentu
//.template hilang karena diperbaiki. Kalau scan terakhirnya lebih dangkal
// atau gagal separuh jalan, endpointnya tetap ada di sana — yang hilang
// cuma dari laporan. Karena itu DiffResults menyimpan cakupan kedua
// scan, dan callers wajib menampilkannya.

// DiffResults menyimpan hasil perbandingan dua scan.
type DiffResults struct {
	Target string
	OldAt  string
	NewAt  string

	NewEndpoints     []string
	RemovedEndpoints []string
	KeptEndpoints    int

	NewFindings      []Finding
	ResolvedFindings []Finding
	KeptFindings     int

	// CoverageComparable menandai apakah kedua scan cukup mirip sehingga
	// endpoint yang hilang layak dipercaya sebagai perubahan nyata.
	//
	// Kalau halaman yang dipindai jauh lebih sedikit pada scan baru, itu
	// scan yang tidak tuntas — bukan perbaikan.
	CoverageComparable bool
	CoverageNote       string

	SeverityDelta map[Severity]int
}

// HasChanges menandai ada tidaknya perubahan nyata.
func (d DiffResults) HasChanges() bool {
	return len(d.NewEndpoints) > 0 || len(d.NewFindings) > 0 ||
		len(d.RemovedEndpoints) > 0 || len(d.ResolvedFindings) > 0
}

// endpointKey mengidentifikasi endpoint antar scan.
//
// Method ikut disertakan karena endpoint yang sama dengan method berbeda
// adalah dua permukaan yang berbeda.
func endpointKey(e Endpoint) string { return e.Method + " " + e.Path }

// findingKey mengidentifikasi temuan antar scan.
//
// Title masuk ke key supaya perubahan detail pada temuan yang sama tetap
// terlihat sebagai perubahan, bukan seolah-oleh tidak ada.
func findingKey(f Finding) string {
	return strings.Join([]string{f.Title, f.Kind, f.Where}, "|")
}

// DiffReports membandingkan scan lama dengan scan baru untuk target yang sama.
//
// newest dianggap_truth dan boleh nggak lengkap; old boleh juga nggak
// lengkap. Hasilnya selalu disertai catatan cakupan supaya pembaca nggak
// salah baca "endpoint hilang" sebagai "endpoint dihapus".
func DiffReports(oldRep, newRep *Report) DiffResults {
	// Tanpa baseline yang sah, yang bisa ditampilkan adalah "scan pertama" —
	// bukan daftar semua endpoint sebagai "yang hilang".
	if newRep == nil {
		return DiffResults{}
	}
	noBaseline := oldRep == nil
	if noBaseline {
		oldRep = &Report{Target: newRep.Target}
	}
	d := DiffResults{
		Target:        newRep.Target,
		OldAt:         oldRep.GeneratedAt.Format("2006-01-02 15:04"),
		NewAt:         newRep.GeneratedAt.Format("2006-01-02 15:04"),
		SeverityDelta: map[Severity]int{},
	}

	oldEp := map[string]bool{}
	for _, e := range oldRep.Endpoints {
		oldEp[endpointKey(e)] = true
	}
	newEp := map[string]bool{}
	for _, e := range newRep.Endpoints {
		newEp[endpointKey(e)] = true
	}
	for k := range newEp {
		if !oldEp[k] {
			d.NewEndpoints = append(d.NewEndpoints, k)
		}
	}
	for k := range oldEp {
		if !newEp[k] {
			d.RemovedEndpoints = append(d.RemovedEndpoints, k)
		}
	}
	d.KeptEndpoints = len(newEp)
	sort.Strings(d.NewEndpoints)
	sort.Strings(d.RemovedEndpoints)

	oldF := map[string]Finding{}
	for _, f := range oldRep.Findings {
		oldF[findingKey(f)] = f
	}
	newF := map[string]Finding{}
	for _, f := range newRep.Findings {
		newF[findingKey(f)] = f
	}
	for k, f := range newF {
		if _, ok := oldF[k]; !ok {
			d.NewFindings = append(d.NewFindings, f)
		} else {
			d.KeptFindings++
		}
	}
	for k, f := range oldF {
		if _, ok := newF[k]; !ok {
			d.ResolvedFindings = append(d.ResolvedFindings, f)
		}
	}
	sortFindings(d.NewFindings)
	sortFindings(d.ResolvedFindings)

	for _, s := range []Severity{SevHigh, SevMedium, SevLow, SevInfo} {
		d.SeverityDelta[s] = countSeverity(newRep.Findings, s) - countSeverity(oldRep.Findings, s)
	}

	d.CoverageComparable, d.CoverageNote = compareCoverage(oldRep, newRep)
	if noBaseline {
		// Tanpa baseline, kemiripan cakupan tidak bisa dinilai sama sekali.
		// Menganggapnya "sebanding" akan membuat "semua endpoint hilang"
		// terbaca sebagai hasil yang sah.
		d.CoverageComparable = false
		d.CoverageNote = "tidak ada scan sebelumnya untuk dijadikan pembanding"
	}
	return d
}

// compareCoverage menilai apakah kedua scan bisa dibandingkan.
//
// Endpoint yang hilang hanya bermakna kalau scan barunya tidak lebih dangkal.
// Kalau halaman turun drastis, atau scan baru gagal, ini bukan perbaikan.
func compareCoverage(oldRep, newRep *Report) (bool, string) {
	var notes []string

	if newRep.RootError != "" {
		notes = append(notes, "scan baru gagal mengambil halaman awal, hasilnya tidak lengkap")
	}
	if oldRep.RootError != "" {
		notes = append(notes, "scan lama gagal mengambil halaman awal, jadi hasilnya tidak bisa dianggap baseline bersih")
	}
	// Toleransi 30%. Scan statis bisa berbeda karena JS dinamis atau
	// perubahan kecil; selisih besar menandakan cakupan yang berbeda.
	if len(oldRep.Pages) > 0 {
		drop := 1 - float64(len(newRep.Pages))/float64(len(oldRep.Pages))
		if drop > 0.3 {
			notes = append(notes, fmt.Sprintf(
				"halaman turun dari %d ke %d — cakupan berbeda, endpoint yang hilang belum tentu hilang sungguhan",
				len(oldRep.Pages), len(newRep.Pages)))
		}
	}
	if len(notes) == 0 {
		return true, ""
	}
	return false, strings.Join(notes, "; ")
}

// sortFindings mengurutkan dari yang paling serius.
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) < sevRank(fs[j].Severity)
		}
		return findingKey(fs[i]) < findingKey(fs[j])
	})
}

func sevRank(s Severity) int {
	switch s {
	case SevHigh:
		return 0
	case SevMedium:
		return 1
	case SevLow:
		return 2
	default:
		return 3
	}
}

// Summary satu kalimat untuk ditampilkan di layar sempit.
func (d DiffResults) Summary() string {
	var parts []string
	if n := len(d.NewFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d temuan baru", n))
	}
	if n := len(d.ResolvedFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d hilang", n))
	}
	if n := len(d.NewEndpoints); n > 0 {
		parts = append(parts, fmt.Sprintf("%d endpoint baru", n))
	}
	if n := len(d.RemovedEndpoints); n > 0 {
		parts = append(parts, fmt.Sprintf("%d endpoint hilang", n))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("tidak ada perubahan sejak %s", d.OldAt)
	}
	return strings.Join(parts, ", ") + " sejak " + d.OldAt
}

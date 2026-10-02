package lumen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Penyimpanan riwayat scan.
//
// Setiap scan disimpan sebagai berkas sendiri, bukan menimpa. Bedanya penting
// untuk yang kedua: tanpa riwayat, "temuan yang sama muncul lagi" tidak bisa
// dibedakan dari "temuan yang benar-benar berulang".
//
// Susunan folder:
//
//	out/index.json              daftar semua run, ringan
//	out/<target-slug>/<stempel>.json   laporan lengkap
//
// Index dibaca untuk daftar di layar beranda; laporan lengkap baru dibaca
// ketika benar-benar dibuka. Membaca seluruh JSON hanya untuk menampilkan
// daftar akan terlalu berat kalau riwayat sudah panjang.

// Stempel waktu untuk nama berkas. UTC supaya urutannya tidak bergantung
// zona waktu perangkat.
const timeLayout = "20060102T150405Z"

// Run adalah satu riwayat scan.
type Run struct {
	Target    string    `json:"target"`
	At        time.Time `json:"at"`
	File      string    `json:"file"` // relatif terhadap folder out
	Endpoints int       `json:"endpoints"`
	Findings  int       `json:"findings"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	ScanMS    int64     `json:"scan_ms"`
	Note      string    `json:"note,omitempty"`
}

// Store adalah kumpulan run milik satu folder output.
type Store struct {
	Dir    string
	runs   []Run
	loaded bool
}

// OpenStore membuka (atau membuat) penyimpanan di folder yang diberikan.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// LoadsIndex membaca daftar run. Folder kosong atau index yang rusak bukan
// kondisi fatal — cukup dimulai dari kosong, karena hasil yang hilang lebih
// mudah ditangani daripada alat yang refuses jalan.
func (s *Store) LoadIndex() error {
	b, err := os.ReadFile(s.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			s.runs = nil
			return nil
		}
		return err
	}
	var runs []Run
	if err := json.Unmarshal(b, &runs); err != nil {
		s.runs = nil
		return nil
	}
	s.runs = runs
	s.sort()
	return nil
}

func (s *Store) indexPath() string { return filepath.Join(s.Dir, "index.json") }

// Runs mengembalikan semua run, terbaru dulu.
//
// Index dimuat otomatis kalau belum. Setiap pemanggilan CLI membuat Store
// baru, jadi tanpa pemuatan otomatis di sini semua pembaca akan melihat
// daftar kosong — gejalanya persis seperti "riwayat mysteriously hilang".
func (s *Store) Runs() []Run {
	if !s.loaded {
		_ = s.LoadIndex()
	}
	s.sort()
	return s.runs
}

// sort mengurutkan terbaru lebih dulu, dengan nama berkas sebagai pemutus
// supaya urutannya stabil ketika dua scan selesai pada detik yang sama.
func (s *Store) sort() {
	sort.SliceStable(s.runs, func(i, j int) bool {
		if !s.runs[i].At.Equal(s.runs[j].At) {
			return s.runs[i].At.After(s.runs[j].At)
		}
		return s.runs[i].File < s.runs[j].File
	})
}

// Targets mengembalikan daftar target unik, beserta jumlah run-nya.
type TargetGroup struct {
	Name   string
	Runs   int
	Latest time.Time
}

// Targets mengelompokkan run per target, urut berdasarkan run terbaru.
func (s *Store) Targets() []TargetGroup {
	seen := map[string]*TargetGroup{}
	var order []string
	for _, r := range s.Runs() {
		g, ok := seen[r.Target]
		if !ok {
			g = &TargetGroup{Name: r.Target, Latest: r.At}
			seen[r.Target] = g
			order = append(order, r.Target)
		}
		g.Runs++
		if r.At.After(g.Latest) {
			g.Latest = r.At
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return seen[order[i]].Latest.After(seen[order[j]].Latest)
	})
	out := make([]TargetGroup, 0, len(order))
	for _, n := range order {
		out = append(out, *seen[n])
	}
	return out
}

// SaveRun menulis laporan ke disk dan mendaftarkannya di index.
//
// Laporan ditulis 0600 karena bisa memuat detail endpoint internal. Kalau
// penulisan index gagal, laporannya tetap ada — hanya daftarnya yang perlu
// dibangun ulang dari folder.
func (s *Store) SaveRun(rep *Report, when time.Time) (Run, error) {
	// Index harus dimuat dulu kalau belum.
	//
	// Tanpa ini, setiap SaveRun menulis index yang hanya berisi run itu
	// saja: tiap pemanggilan CLI menimpa index.json, dan riwayat tinggal satu item padahal berkasnya semua masih ada di disk. Kehilangan ini
	// diam-diam — tidak ada error, hanya tidak ada bedanya "scan pertama"
	// dengan "scan kedua".
	if !s.loaded {
		_ = s.LoadIndex()
	}

	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Run{}, err
	}
	slug := slugify(rep.Target)
	sub := filepath.Join(s.Dir, slug)
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return Run{}, err
	}
	stamp := when.UTC().Format(timeLayout)
	name := stamp + ".json"
	full := filepath.Join(sub, name)

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Run{}, err
	}
	if err := os.WriteFile(full, b, 0o600); err != nil {
		return Run{}, err
	}

	run := Run{
		Target:    rep.Target,
		At:        when.UTC(),
		File:      filepath.Join(slug, name),
		Endpoints: len(rep.Endpoints),
		Findings:  len(rep.Findings),
		ScanMS:    rep.DurationMS,
	}
	for _, f := range rep.Findings {
		switch f.Severity {
		case SevHigh:
			run.High++
		case SevMedium:
			run.Medium++
		}
	}
	s.runs = append(s.runs, run)
	s.sort()
	if err := s.saveIndex(); err != nil {
		return run, err
	}
	return run, nil
}

// LoadRun membaca kembali laporan sebuah run.
func (s *Store) LoadRun(r Run) (*Report, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, r.File))
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("laporan %s rusak: %w", r.File, err)
	}
	return &rep, nil
}

// RebuildIndex membangun ulang index dari berkas yang ada di disk.
//
// Dipakai kalau index hilang atau tidak sinkron dengan isi folder — misalnya
// setelah menyalin folder output ke tempat lain.
func (s *Store) RebuildIndex() (int, error) {
	var runs []Run
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			rel := filepath.Join(e.Name(), f.Name())
			b, err := os.ReadFile(filepath.Join(s.Dir, rel))
			if err != nil {
				continue
			}
			var rep Report
			if err := json.Unmarshal(b, &rep); err != nil {
				continue
			}
			at := rep.GeneratedAt
			if at.IsZero() {
				if t, err := time.Parse(timeLayout, strings.TrimSuffix(f.Name(), ".json")); err == nil {
					at = t
				}
			}
			run := Run{
				Target: rep.Target, At: at, File: rel,
				Endpoints: len(rep.Endpoints), Findings: len(rep.Findings),
				ScanMS: rep.DurationMS,
			}
			for _, fd := range rep.Findings {
				switch fd.Severity {
				case SevHigh:
					run.High++
				case SevMedium:
					run.Medium++
				}
			}
			runs = append(runs, run)
		}
	}
	s.runs = runs
	s.sort()
	if err := s.saveIndex(); err != nil {
		return len(runs), err
	}
	return len(runs), nil
}

func (s *Store) saveIndex() error {
	b, err := json.MarshalIndent(s.runs, "", "  ")
	if err != nil {
		return err
	}
	// Ditulis lewat berkas sementara lalu di-rename supaya index tidak pernah
	// tertinggal setengah tertulis kalau proses mati di tengah jalan.
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath())
}

// slugify mengubah URL menjadi nama folder yang aman.
func slugify(raw string) string {
	s := raw
	for _, p := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, p)
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		default:
			out = append(out, '-')
		}
	}
	res := strings.Trim(string(out), "-")
	if res == "" {
		return "target"
	}
	if len(res) > 80 {
		res = res[:80]
	}
	return res
}

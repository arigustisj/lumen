package lumen

import "errors"

// LatestTwo mengembalikan dua run terakhir untuk sebuah target, terbaru dulu.
//
// Dipakai untuk diff: baseline selalu scan sebelumnya untuk target yang sama,
// bukan run terakhir secara global — membandingkan antar target tidak punya
// arti.
func (s *Store) LatestTwo(target string) (*Run, *Run, error) {
	var matched []Run
	for _, r := range s.Runs() {
		if r.Target == target || stripScheme(r.Target) == stripScheme(target) {
			matched = append(matched, r)
		}
	}
	switch len(matched) {
	case 0:
		return nil, nil, errors.New("belum ada riwayat scan untuk target ini")
	case 1:
		return &matched[0], nil, nil
	default:
		return &matched[0], &matched[1], nil
	}
}

// LoadPair memuat laporan dari dua run, terbaru lebih dulu.
func (s *Store) LoadPair(newer, older *Run) (*Report, *Report, error) {
	if newer == nil {
		return nil, nil, errors.New("run tidak ditemukan")
	}
	nr, err := s.LoadRun(*newer)
	if err != nil {
		return nil, nil, err
	}
	if older == nil {
		return nr, nil, nil
	}
	or, err := s.LoadRun(*older)
	if err != nil {
		return nil, nil, err
	}
	return nr, or, nil
}

// DiffAgainstPrevious membandingkan sebuah laporan dengan scan sebelumnya
// untuk target yang sama.
//
// Kalau laporan itu sendiri adalah scan terbaru, yang dibandingkan adalah
// run sebelum baseline-nya — supaya "terakhir" dan "sebelumnya" tidak
// tertukar.
//
// Mengembalikan nil kalau tidak ada baseline. Pemanggil wajib menangani
// nil sebagai "belum bisa dinilai", bukan sebagai "tidak ada perubahan".
func (s *Store) DiffAgainstPrevious(rep *Report) *DiffResults {
	if rep == nil {
		return nil
	}
	var matched []Run
	for _, r := range s.Runs() {
		if r.Target == rep.Target || stripScheme(r.Target) == stripScheme(rep.Target) {
			matched = append(matched, r)
		}
	}

	// Cari posisi laporan ini di riwayat. Kalau tidak ketemu (misalnya
	// laporan yang dihitung ulang di luar store), pakai run terakhir yang
	// waktunya berbeda.
	var base *Run
	for _, r := range matched {
		if r.At.Equal(rep.GeneratedAt) {
			if idx := indexOfRun(matched, r); idx >= 0 && idx+1 < len(matched) {
				base = &matched[idx+1]
			}
			break
		}
	}
	if base == nil && len(matched) > 0 {
		last := matched[0]
		if !last.At.Equal(rep.GeneratedAt) {
			base = &last
		}
	}
	if base == nil {
		return nil
	}
	oldRep, err := s.LoadRun(*base)
	if err != nil {
		return nil
	}
	d := DiffReports(oldRep, rep)
	return &d
}

func indexOfRun(runs []Run, want Run) int {
	for i := range runs {
		if runs[i].File == want.File {
			return i
		}
	}
	return -1
}

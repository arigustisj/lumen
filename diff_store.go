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

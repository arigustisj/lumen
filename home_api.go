package lumen

// Facade exported untuk beranda.
//
// Model di dalam sengaja tidak exported: nama-namanya (mode, sel, run) hanya
// punya arti di dalam package ini, dan mengeksposnya berarti mengunci
// struktur internal sebagai bagian dari API publik.
//
// Yang diekspor hanya yang benar-benar dipakai pemanggil: cara membuat,
// mengirim ukuran, meneruskan ketikan, dan menggambar.

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// HomeModel adalah layar beranda: daftar target yang pernah dipindai,
// riwayat run untuk masing-masing, dan kolom input untuk target baru.
type HomeModel struct {
	m *homeModel
}

// NewHomeModel membuat beranda untuk folder output tertentu.
//
// Folder yang tidak ada akan dibuat. Index yang hilang atau rusak tidak
// dianggap error: daftar dimulai kosong dan bisa dibangun ulang dengan
// RebuildIndex.
func NewHomeModel(store *Store) *HomeModel {
	return &HomeModel{m: newHome(store)}
}

// Reload membaca ulang daftar dari disk.
func (h *HomeModel) Reload() { h.m.reload() }

// SetStatus menampilkan pesan singkat di footer.
func (h *HomeModel) SetStatus(msg string) {
	h.m.statusMsg = msg
	h.m.statusErr = ""
}

// UpdateSize menyimpan ukuran terminal.
func (h *HomeModel) UpdateSize(w, hh int) { h.m.updateSize(w, hh) }

// Width mengembalikan lebar terakhir yang diketahui.
func (h *HomeModel) Width() int { return h.m.w }

// Height mengembalikan tinggi terakhir yang diketahui.
func (h *HomeModel) Height() int { return h.m.h }

// Action apa yang diminta pemanggil setelah tombol ditekan.
type HomeAction struct {
	// Kind: "newscan", "open", atau "quit".
	Kind string
	// Target diisi untuk "newscan".
	Target string
	// Run diisi untuk "open".
	Run *Run
}

// Update meneruskan satu ketikan.
//
// Tombol khusus yang bukan teks biasa dipetakan ke msg "up"/"down"/"enter"
// supaya pemanggil tidak perlu tahu detail pengetikan.
func (h *HomeModel) Update(msg tea.KeyMsg) HomeAction {
	k := msg.String()
	act, run := h.m.update(k)
	switch {
	case act == "quit":
		return HomeAction{Kind: "quit"}
	case act == "open" && run != nil:
		r := *run
		return HomeAction{Kind: "open", Run: &r}
	case strings.HasPrefix(act, "newscan:"):
		return HomeAction{Kind: "newscan", Target: strings.TrimPrefix(act, "newscan:")}
	}
	return HomeAction{}
}

// View menggambar isi beranda.
func (h *HomeModel) View() string { return h.m.view() }

// Footer menggambar baris pintasan.
func (h *HomeModel) Footer() string { return h.m.footer() }

// LoadedReport menyiapkan model laporan untuk run yang sudah tersimpan.
//
// Layar pembuka dilewati: report lama bukan hasil scan baru, dan pengguna
// yang membukanya sudah pernah melihat pemukaannya di scan pertama.
// Menampilkannya lagi hanya menambah satu keystroke sebelum isi.
func (h *HomeModel) LoadedReport(rep *Report, cands []Candidate, cov Coverage, authz []AuthzReport) *TUIModel {
	m := NewTUIModel(rep.Target)
	m.Seed(rep, cands, cov, authz)
	m.SkipIntro()
	// Laporan lama ikut dibandingkan dengan scan sebelumnya supaya panel
	// Perubahan tidak kosong hanya karena yang dibuka bukan scan terakhir.
	m.SetDiff(h.m.store.DiffAgainstPrevious(rep))
	return m
}

// ViewScanning menggambar layar saat pemetaan berjalan.
func (h *HomeModel) ViewScanning(targetURL string) string {
	m := &TUIModel{target: targetURL, phase: PhaseScanning, width: h.m.w, height: h.m.h}
	m.compact = h.m.w < 72
	return m.viewScanning()
}

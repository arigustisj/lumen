package lumen

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestInputKetikURL(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.UpdateSize(90, 30)

	if act := h.Update(key("n")); act.Kind != "" {
		t.Fatalf("n di beranda tidak boleh langsung menjalankan apa pun, dapat %q", act.Kind)
	}
	if h.View() == "" || !hasStr(h.View(), "Scan target baru") {
		t.Fatal("n tidak membuka mode input")
	}

	for _, k := range "app.kantor.id" {
		h.Update(key(string(k)))
	}
	act := h.Update(key("enter"))
	if act.Kind != "newscan" {
		t.Fatalf("enter harus memicu newscan, dapat %q", act.Kind)
	}
	if act.Target != "https://app.kantor.id" {
		t.Fatalf("skema harus ditambahkan otomatis, dapat %q", act.Target)
	}
}

func TestInputURLLengkapTetapAsli(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.Update(key("n"))
	for _, k := range "http://staging.kantor.internal:8080/api" {
		h.Update(key(string(k)))
	}
	act := h.Update(key("enter"))
	if act.Target != "http://staging.kantor.internal:8080/api" {
		t.Fatalf("URL yang sudah punya skema tidak boleh diubah, dapat %q", act.Target)
	}
}

func TestInputEscMembatalkanDanTidakMenjalankan(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.Update(key("n"))
	for _, k := range "example.com" {
		h.Update(key(string(k)))
	}
	if act := h.Update(key("esc")); act.Kind != "" {
		t.Fatalf("esc harus batal tanpa menjalankan scan, dapat %q", act.Kind)
	}
	if hasStr(h.View(), "Scan target baru") {
		t.Fatal("esc harus menutup layar input")
	}
	if !hasStr(h.View(), "Belum ada riwayat") {
		t.Fatalf("esc harus kembali ke daftar target, dapat:\n%s", h.View())
	}
}

func TestInputKosongDitolak(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.Update(key("n"))
	if act := h.Update(key("enter")); act.Kind != "" {
		t.Fatal("URL kosong tidak boleh memicu scan")
	}
	if !hasStr(h.Footer()+h.View(), "kosong") {
		t.Fatal("URL kosong harus diberi tahu ke pengguna")
	}
}

func TestInputKontrolKata(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.Update(key("n"))
	for _, k := range "salah host.example" {
		h.Update(key(string(k)))
	}
	h.Update(key("ctrl+w"))
	act := h.Update(key("enter"))
	// ctrl+w menghapus kata sebelum kursor beserta spasi pemisah, jadi
	// "salah host.example" menjadi "salah".
	if act.Target != "https://salah" {
		t.Fatalf("ctrl+w menghapus kata sebelum kursor; sisa harus \"salah\", dapat %q", act.Target)
	}
	h.Update(key("ctrl+u"))
	if act := h.Update(key("enter")); act.Kind != "" {
		t.Fatal("ctrl+u harus mengosongkan input")
	}
}

func mustStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// key membuat tea.KeyMsg dari nama tombol seperti yang dipakai Update.
//
// Penting: tombol khusus harus memakai tipe Key yang benar. Kalau "esc"
// dikirim sebagai rune, String() akan mengembalikan "esc" sebagai teks dan
// cabangnya tidak akan pernah_reviewed — test jadi lulus tanpa menguji apa pun.
func key(k string) tea.KeyMsg {
	switch k {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "ctrl+w":
		return tea.KeyMsg{Type: tea.KeyCtrlW}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

func hasStr(hay, needle string) bool { return strings.Contains(hay, needle) }

func TestInputMenerimaPasteURL(t *testing.T) {
	h := NewHomeModel(mustStore(t))
	h.Update(key("n"))
	// Satu KeyMsg berisi seluruh teks, seperti yang dikirim Bubble Tea
	// untuk tempelan.
	h.Update(key("https://staging.kantor.internal"))
	act := h.Update(key("enter"))
	if act.Kind != "newscan" {
		t.Fatalf("paste URL harus memicu newscan, dapat %q", act.Kind)
	}
	if act.Target != "https://staging.kantor.internal" {
		t.Fatalf("paste URL harus masuk utuh, dapat %q", act.Target)
	}
}

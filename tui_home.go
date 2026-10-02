package lumen

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Layar beranda.
//
// Alasan layar ini ada: hasil scan adalah hal yang jarang terjadi, tapi
// membacanya yang sering. Kalau setiap kemunculan tool langsung，尤其是在
// HP dengan keyboard virtual, memaksa mengetik URL yang sama berulang kali —
// dan hasil scan sebelumnya jadi tidak pernah dibuka.
//
// Jadi: masuk dulu ke daftar, pilih target, baru lihat. Scan baru tetap
// tersedia tapi tidak jadi jalur utama.

type homeMode int

const (
	homeTargets homeMode = iota // daftar target
	homeRuns                    // riwayat run untuk satu target
	homeInput                   // mengetik URL untuk scan baru
)

// Model beranda.
type homeModel struct {
	store *Store
	mode  homeMode

	targets []TargetGroup
	selT    int

	selected  string // target yang sedang lihat riwayatnya
	runs      []Run
	selR      int
	statusMsg string

	// Input URL. Ditulis sendiri, bukan memakai bubbles/textinput,
	// supaya tidak menambah dependency untuk satu baris teks.
	input     string
	cursor    int
	prompt    string
	statusErr string

	w, h   int
	scroll int
}

func newHome(store *Store) *homeModel {
	m := &homeModel{store: store}
	m.reload()
	return m
}

// openInput masuk ke mode mengetik URL.
func (m *homeModel) openInput(prefill string) {
	m.mode = homeInput
	m.input = prefill
	m.cursor = len([]rune(prefill))
	m.prompt = "https://app.example.com"
	m.statusMsg = ""
	m.statusErr = ""
}

// normaliseTarget menambahkan skema bila lupa diketik.
func normaliseTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return "https://" + s
	}
	return s
}

// inputUpdate menangani ketikan di mode input.
//
// Enter mengembalikan URL yang sudah dinormalisasi. Escape membatalkan.
func (m *homeModel) inputUpdate(k string) (done bool, target string) {
	r := []rune(m.input)
	switch k {
	case "enter":
		t := normaliseTarget(m.input)
		if t == "" {
			m.statusErr = "URL tidak boleh kosong"
			return false, ""
		}
		if _, err := url.Parse(t); err != nil {
			m.statusErr = "URL tidak bisa dibaca: " + err.Error()
			return false, ""
		}
		return true, t
	case "esc":
		m.mode = homeTargets
		m.statusErr = ""
		return false, ""
	case "backspace":
		if m.cursor > 0 {
			m.input = string(r[:m.cursor-1]) + string(r[m.cursor:])
			m.cursor--
		}
		m.statusErr = ""
	case "delete":
		if m.cursor < len(r) {
			m.input = string(r[:m.cursor]) + string(r[m.cursor+1:])
		}
	case "left":
		if m.cursor > 0 {
			m.cursor--
		}
	case "right":
		if m.cursor < len(r) {
			m.cursor++
		}
	case "home", "ctrl+a":
		m.cursor = 0
	case "end", "ctrl+e":
		m.cursor = len(r)
	case "ctrl+u":
		m.input = ""
		m.cursor = 0
		m.statusErr = ""
	case "ctrl+w":
		if m.cursor > 0 {
			left := string(r[:m.cursor])
			if i := strings.LastIndexFunc(left, func(x rune) bool { return x == ' ' }); i >= 0 {
				m.input = left[:i] + string(r[m.cursor:])
				m.cursor = i
			} else {
				m.input = string(r[m.cursor:])
				m.cursor = 0
			}
		}
	default:
		// Sisipkan semua rune sekaligus, bukan hanya satu.
		//
		// Bubble Tea mengirim tempelan sebagai satu KeyMsg yang Runes-nya
		// berisi seluruh teks. Kalau hanya `len(k) == 1` yang diterima,
		// setiap paste URL jadi tidak masuk sama sekali — persis kasus yang
		// paling sering terjadi di Termux, tempat URL sering ditempel.
		if rr := []rune(k); len(rr) > 0 {
			m.input = string(r[:m.cursor]) + string(rr) + string(r[m.cursor:])
			m.cursor += len(rr)
			m.statusErr = ""
		}
	}
	return false, ""
}

func (m *homeModel) reload() {
	_ = m.store.LoadIndex()
	m.targets = m.store.Targets()
	if m.selT >= len(m.targets) {
		m.selT = maxInt(0, len(m.targets)-1)
	}
}

func (m *homeModel) current() *TargetGroup {
	if len(m.targets) == 0 {
		return nil
	}
	if m.selT < 0 || m.selT >= len(m.targets) {
		return nil
	}
	return &m.targets[m.selT]
}

func (m *homeModel) currentRun() *Run {
	if m.mode != homeRuns || m.selR < 0 || m.selR >= len(m.runs) {
		return nil
	}
	return &m.runs[m.selR]
}

func (m *homeModel) updateSize(w, h int) { m.w, m.h = w, h }

func (m *homeModel) update(msg string) (action string, run *Run) {
	// Mode input memegang semua ketikan sampai selesai atau dibatalkan.
	if m.mode == homeInput {
		if done, t := m.inputUpdate(msg); done {
			m.mode = homeTargets
			return "newscan:" + t, nil
		}
		return "", nil
	}

	switch msg {
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "home":
		m.jump(0)
	case "end":
		m.jump(1 << 30)
	case "pgup":
		m.move(-8)
	case "pgdown":
		m.move(8)
	case "enter", "l", "right":
		return m.openSelected()
	case "esc", "h", "left", "backspace":
		if m.mode == homeRuns {
			m.mode = homeTargets
			m.selected = ""
			m.statusMsg = ""
			return "", nil
		}
		return "quit", nil
	case "r":
		m.reload()
		m.statusMsg = "daftar diperbarui"
	case "n":
		m.openInput("")
		return "", nil
	case "s":
		// Scan ulang target terpilih tanpa mengetik URL lagi. Ini yang
		// paling sering dipakai setelah pertama, jadi harus satu tombol.
		if g := m.current(); g != nil {
			return "newscan:" + g.Name, nil
		}
		m.statusMsg = "pilih target dulu dengan ↑↓"
	}
	return "", nil
}

func (m *homeModel) move(d int) {
	switch m.mode {
	case homeTargets:
		m.selT = clamp(m.selT+d, 0, maxInt(0, len(m.targets)-1))
	case homeRuns:
		m.selR = clamp(m.selR+d, 0, maxInt(0, len(m.runs)-1))
	}
}

func (m *homeModel) jump(i int) {
	switch m.mode {
	case homeTargets:
		m.selT = clamp(i, 0, maxInt(0, len(m.targets)-1))
	case homeRuns:
		m.selR = clamp(i, 0, maxInt(0, len(m.runs)-1))
	}
}

// openSelected masuk ke riwayat atau membuka laporan.
func (m *homeModel) openSelected() (string, *Run) {
	switch m.mode {
	case homeTargets:
		g := m.current()
		if g == nil {
			m.statusMsg = "belum ada riwayat. tekan n untuk scan baru"
			return "", nil
		}
		m.selected = g.Name
		m.mode = homeRuns
		m.selR = 0 // run terbaru lebih dulu
		m.runs = m.store.Runs()
		// Hanya run milik target terpilih.
		var only []Run
		for _, r := range m.runs {
			if r.Target == g.Name {
				only = append(only, r)
			}
		}
		m.runs = only
		return "", nil
	case homeRuns:
		r := m.currentRun()
		if r == nil {
			return "", nil
		}
		return "open", r
	}
	return "", nil
}

func (m *homeModel) view() string {
	switch m.mode {
	case homeRuns:
		return m.viewRuns()
	case homeInput:
		return m.viewInput()
	}
	return m.viewTargets()
}

func (m *homeModel) viewInput() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cAccent).Render("Scan target baru") + "\n\n")

	shown := m.input
	if shown == "" {
		shown = m.prompt
	}
	// Kursor berhasil|tampil supaya jelas bahwa ini field yang bisa diisi.
	caret := lipgloss.NewStyle().Foreground(cBrand).Reverse(true).Render(" ")
	if m.cursor < len([]rune(shown)) {
		pre := string([]rune(shown)[:m.cursor])
		cur := string([]rune(shown)[m.cursor])
		caret = lipgloss.NewStyle().Foreground(cBrand).Reverse(true).Render(cur)
		shown = pre + caret + string([]rune(shown)[m.cursor+1:])
	} else {
		shown += caret
	}
	style := lipgloss.NewStyle().Foreground(cText)
	if m.input == "" {
		style = lipgloss.NewStyle().Foreground(cDim)
	}
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).Render("URL  ") + style.Render(shown) + "\n\n")

	if m.statusErr != "" {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cHigh).Render(m.statusErr) + "\n\n")
	}
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).
		Render("enter scan · esc batal · ctrl+w hapus kata · ctrl+u kosongkan") + "\n")
	return b.String()
}

func (m *homeModel) viewTargets() string {
	var b strings.Builder
	b.WriteString("\n")
	for _, l := range bigTitle {
		if lipgloss.Width(l) <= m.w-2 {
			b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(" "+l) + "\n")
		}
	}
	if lipgloss.Width(bigTitle[0]) > m.w-2 {
		for _, l := range smallTitle {
			b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(" "+l) + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).
		Render(Tagline+"  "+gArrow+"  by "+Author) + "\n\n")

	if len(m.targets) == 0 {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cMedium).
			Render("Belum ada riwayat scan") + "\n\n")
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).
			Render("tekan n untuk mulai scan pertama") + "\n")
		return b.String()
	}

	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cAccent).
		Render(fmt.Sprintf("Riwayat scan (%d target)", len(m.targets))) + "\n\n")

	rows := m.visibleTargets()
	for i, idx := range rows {
		g := m.targets[idx]
		active := idx == m.selT
		badge := lipgloss.NewStyle().Foreground(cDim).Render(fmt.Sprint(g.Runs) + "×")
		// Severity badge menentukan urutan-even yang terlihat saat menggulir.
		sev := "   "
		for _, r := range m.runsOf(g.Name) {
			if r.High > 0 {
				sev = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111b")).
					Background(cHigh).Render(" HIGH")
				break
			}
			if r.Medium > 0 {
				sev = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111b")).
					Background(cMedium).Render(" MED ")
			}
		}
		when := relTime(m.w, g.Latest)
		name := stripScheme(g.Name)
		if active {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(cBrand).Bold(true).
				Render("▸ "+name) + "  " + sev + "  " +
				lipgloss.NewStyle().Foreground(cDim).Render(when+" "+badge) + "\n")
		} else {
			b.WriteString("    " + lipgloss.NewStyle().Foreground(cText).Render(name) + "  " + sev + "  " +
				lipgloss.NewStyle().Foreground(cDim).Render(when+" "+badge) + "\n")
		}
		_ = i
	}
	return b.String()
}

func (m *homeModel) runsOf(target string) []Run {
	var out []Run
	for _, r := range m.store.Runs() {
		if r.Target == target {
			out = append(out, r)
		}
	}
	return out
}

func (m *homeModel) visibleTargets() []int {
	h := m.bodyHeight()
	start := 0
	if m.selT >= h {
		start = m.selT - h + 1
	}
	end := start + h
	if end > len(m.targets) {
		end = len(m.targets)
	}
	var out []int
	for i := start; i < end; i++ {
		out = append(out, i)
	}
	return out
}

func (m *homeModel) viewRuns() string {
	var b strings.Builder
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cAccent).
		Render(stripScheme(m.selected)) + "\n")
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).
		Render(fmt.Sprintf("%d riwayat scan · esc untuk kembali", len(m.runs))) + "\n\n")

	if len(m.runs) == 0 {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cMedium).Render("tidak ada run") + "\n")
		return b.String()
	}

	h := m.bodyHeight()
	start := 0
	if m.selR >= h {
		start = m.selR - h + 1
	}
	end := minInt(start+h, len(m.runs))
	for i := start; i < end; i++ {
		r := m.runs[i]
		sev := lipgloss.NewStyle().Foreground(cLow).Render("bersih")
		if r.High > 0 {
			sev = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111b")).
				Background(cHigh).Render(fmt.Sprintf(" %d HIGH ", r.High))
		} else if r.Medium > 0 {
			sev = lipgloss.NewStyle().Foreground(lipgloss.Color("#11111b")).
				Background(cMedium).Render(fmt.Sprintf(" %d MED ", r.Medium))
		}
		meta := lipgloss.NewStyle().Foreground(cDim).Render(fmt.Sprintf("%d endpoint · %d temuan · %s",
			r.Endpoints, r.Findings, fmtDuration(r.ScanMS)))
		if i == m.selR {
			b.WriteString("  " + lipgloss.NewStyle().Foreground(cBrand).Bold(true).
				Render("▸ "+r.At.Local().Format("02 Jan 15:04")) + "  " + sev + "  " + meta + "\n")
		} else {
			b.WriteString("    " + lipgloss.NewStyle().Foreground(cText).
				Render(r.At.Local().Format("02 Jan 15:04")) + "  " + sev + "  " + meta + "\n")
		}
	}
	return b.String()
}

func (m *homeModel) bodyHeight() int {
	h := m.h - 14 // header + judul + footer
	if h < 3 {
		h = 3
	}
	return h
}

func (m *homeModel) footer() string {
	var hints string
	switch m.mode {
	case homeRuns:
		hints = "↑↓ pilih · enter buka laporan · esc kembali · q keluar"
	case homeInput:
		hints = "ketik URL · enter scan · esc batal"
	default:
		hints = "↑↓ pilih · enter riwayat · s scan ulang · n scan baru · q keluar"
	}
	if m.statusMsg != "" {
		hints = m.statusMsg + "   ·   " + hints
	}
	return " " + lipgloss.NewStyle().Foreground(cDim).Render(hints)
}

// relTime menulis waktu relatif yang muat di terminal sempit. Di layar HP,
// tanggal lengkap eats ruang yang lebih penting dipakai nama target.
func relTime(w int, t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "baru saja"
	case d < time.Hour:
		return fmt.Sprintf("%d menit lalu", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d jam lalu", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%d hari lalu", int(d.Hours()/24))
	default:
		return t.Format("02 Jan")
	}
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

package lumen

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	railWidth    = 14
	headerHeight = 1
	footerHeight = 1
)

// Palette. Warna didefinisikan sebagai konstanta supaya tidak ada string
// warna hex yang tercecer di seluruh file.
var (
	cBorder   = lipgloss.Color("#3b4252")
	cBorderHi = lipgloss.Color("#7aa2f7")
	cText     = lipgloss.Color("#c0caf5")
	cDim      = lipgloss.Color("#565f89")
	cAccent   = lipgloss.Color("#7aa2f7")
	cHigh     = lipgloss.Color("#f7768e")
	cMedium   = lipgloss.Color("#e0af68")
	cLow      = lipgloss.Color("#9ece6a")
	cInfo     = lipgloss.Color("#7dcfff")
	cBrand    = lipgloss.Color("#bb9af7")
)

var (
	stBorder   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorder)
	stBorderHi = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cBorderHi)
	stTitle    = lipgloss.NewStyle().Bold(true).Foreground(cAccent)
	stTitleHi  = lipgloss.NewStyle().Bold(true).Foreground(cBrand)
	stDim      = lipgloss.NewStyle().Foreground(cDim)
	stAccent   = lipgloss.NewStyle().Foreground(cAccent)
)

// View menyusun seluruh tampilan.
func (m *TUIModel) View() string {
	if m.quit {
		return ""
	}
	if m.width == 0 {
		return "memuat…"
	}
	if m.showHelp {
		return m.viewHelp()
	}

	var b strings.Builder
	b.WriteString(m.viewHeader())
	b.WriteString("\n")
	b.WriteString(m.viewBody())
	b.WriteString("\n")
	b.WriteString(m.viewFooter())
	return b.String()
}

func (m *TUIModel) viewHeader() string {
	left := lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(Name + " " + Version)
	right := lipgloss.NewStyle().Foreground(cDim).Render(m.target)

	if m.compact {
		return left + " " + right
	}
	w := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if w < 1 {
		w = 1
	}
	return left + strings.Repeat(" ", w) + right
}

func (m *TUIModel) viewFooter() string {
	hints := "↑↓ panel · pgup/pgdn gulir · ? bantuan · q keluar"
	if m.compact {
		hints = "↑↓ · ? · q"
	}
	if m.phase != PhaseDone {
		hints = "memindai… · q keluar"
	}
	st := stDim
	if m.phase == PhaseDone {
		st = lipgloss.NewStyle().Foreground(cLow)
		hints += " · r scan ulang"
	}
	leftText := " " + hints
	rightText := ""
	if m.phase == PhaseDone && m.rep != nil {
		rightText = fmt.Sprintf("%d endpoint · %d temuan", len(m.rep.Endpoints), len(m.rep.Findings))
	}

	// Salah satu dari dua sisi boleh dipotong, tapi tidak boleh keduanya
	// hilang: kalau tidak muat, angka ringkasan yang hilang lebihemdalam
	// comparado daftar pintasan.
	rightW := 0
	if rightText != "" {
		rightW = lipgloss.Width(rightText) + 1
	}
	if leftW := lipgloss.Width(leftText); leftW+rightW > m.width {
		room := m.width - rightW
		if room < 6 {
			room = m.width
			rightText = ""
			rightW = 0
		}
		leftText = truncRight(leftText, room)
	}
	left := st.Render(leftText)
	if rightText == "" {
		return left
	}
	right := lipgloss.NewStyle().Foreground(cDim).Render(rightText)
	w := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if w < 1 {
		w = 1
	}
	return left + strings.Repeat(" ", w) + right
}

// viewBody menghasilkan rail navigasi + konten, atau spinner kalau masih
// memindai.
func (m *TUIModel) viewBody() string {
	switch m.phase {
	case PhaseScanning:
		return m.viewScanning()
	case PhaseFailed:
		return m.viewFailed()
	}

	p := panels[m.focus]
	content := p.Render(m, m.contentWidth(), m.contentHeight())

	// Potong isi sesuai posisi scroll, lalu batasi tinggi supaya tidak
	// menabrak footer.
	lines := strings.Split(content, "\n")
	top := m.scroll[p.Key]
	if top > len(lines)-1 {
		top = len(lines) - 1
	}
	if top < 0 {
		top = 0
	}
	end := top + m.contentHeight()
	if end > len(lines) {
		end = len(lines)
	}
	visible := lines[top:end]
	for len(visible) < m.contentHeight() {
		visible = append(visible, "")
	}

	if m.compact {
		// Di layar sempit rail disembunyikan dan judul panel ditaruh di
		// atas konten. Rail 14 kolom di layar 40 kolom berarti area konten
		// tinggal 26 — terlalu sempit untuk membaca path.
		head := lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(p.Title)
		return lipgloss.JoinVertical(lipgloss.Left, head, strings.Join(visible, "\n"))
	}

	rail := m.viewRail()
	body := lipgloss.JoinHorizontal(lipgloss.Top, rail, "\n", strings.Join(visible, "\n"))
	return body
}

func (m *TUIModel) viewRail() string {
	var rows []string
	for i, p := range panels {
		active := i == m.focus
		label := " " + p.Title
		if active {
			rows = append(rows, lipgloss.NewStyle().Bold(true).
				Foreground(cBrand).Background(lipgloss.Color("#1f2335")).Render(pad(label, railWidth)))
			continue
		}
		// Judul panel yang punya isi diberi tanda, supaya navigasi
		// memberi informasi sebelum user mengalaminya.
		badge := ""
		if n := m.panelCount(p.Key); n > 0 {
			badge = fmt.Sprintf(" %d", n)
		}
		label += badge
		rows = append(rows, lipgloss.NewStyle().Foreground(cDim).Render(pad(label, railWidth)))
	}
	return lipgloss.JoinVertical(lipgloss.Left, rows...)
}

// panelCount memberi tahu berapa banyak isi yang menonjol di tiap panel,
// supaya rail navigasi tidak cuma daftar kosong.
func (m *TUIModel) panelCount(key string) int {
	if m.rep == nil {
		return 0
	}
	switch key {
	case "temuan":
		return len(m.rep.Findings)
	case "endpoint":
		return len(m.rep.Endpoints)
	case "kandidat":
		return len(m.cands)
	case "authz":
		n := 0
		for _, ar := range m.authz {
			for _, r := range ar.Results {
				if r.Verdict != "" && r.Verdict != "seimbang" && r.Verdict != "tidak-ada-baseline" {
					n++
				}
			}
		}
		return n
	case "cakupan":
		return len(m.cov.NotTested)
	}
	return 0
}

func (m *TUIModel) viewScanning() string {
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[m.tick%10]
	head := lipgloss.NewStyle().Bold(true).Foreground(cBrand).
		Render(spinner + " memetakan permukaan " + m.target)
	sub := stDim.Render("halaman: " + fmt.Sprint(m.pages) +
		" · tetapkan dengan -probe=false agar lebih cepat")

	w := m.contentWidth()
	if w < 40 {
		w = 40
	}
	body := head + "\n\n" + sub
	return stBorder.Width(w-2).Padding(0, 1).Render(body)
}

func (m *TUIModel) viewFailed() string {
	msg := "gagal memindai"
	if m.err != nil {
		msg = m.err.Error()
	}
	body := lipgloss.NewStyle().Bold(true).Foreground(cHigh).Render(msg) +
		"\n\n" + stDim.Render("r — coba lagi    q — keluar")
	w := m.contentWidth()
	return stBorder.Width(w-2).Padding(0, 1).Render(body)
}

func (m *TUIModel) viewHelp() string {
	rows := [][2]string{
		{"↑ / k", "fokus panel di atas"},
		{"↓ / j", "fokus panel di bawah"},
		{"pgup / pgdn", "gulung isi panel"},
		{"home / end", "ke atas / bawah isi"},
		{"tab / shift+tab", "ganti fokus"},
		{"r", "pindai ulang"},
		{"q / ctrl+c", "keluar"},
		{"?", "tutup bantuan ini"},
	}
	var b strings.Builder
	b.WriteString(stTitleHi.Render("  Pintasan") + "\n\n")
	for _, r := range rows {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cAccent).Width(18).Render(r[0]) +
			stDim.Render(r[1]) + "\n")
	}
	b.WriteString("\n")
	b.WriteString("  " + stDim.Render("Hanya GET dan OPTIONS yang dikirim. Tidak ada metode yang mengubah state.") + "\n")
	b.WriteString("  " + stDim.Render("Laporan ditulis ke folder out/ dengan mode 0600."))
	w := m.contentWidth()
	if w < 30 {
		w = 30
	}
	return stBorder.Width(w-2).Padding(0, 1).Render(b.String())
}

// pad menambahkan spasi di kanan sampai lebar tertentu, dengan aman pada
// karakter multi-byte.
func pad(s string, w int) string {
	n := w - lipgloss.Width(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

var _ tea.Model = (*TUIModel)(nil)

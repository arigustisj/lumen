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

	// Scan yang gagal total harus terlihat sebagai kegagalan, bukan sebagai
	// laporan kosong. "0 endpoint" dan "belum sempat konek" artinya dua hal
	// yang sama sekali berbeda, dan hanya yang pertama yang aman disimpulkan.
	//
	// Diperiksa SEBELUM layar pembuka: menampilkan judul besar dengan
	// angka nol untuk scan yang gagal hanya menambahkan satu langkah
	// sekaligusego mengulang ilusi yang sama.
	if m.rep != nil && m.rep.RootError != "" {
		return m.viewRootError()
	}

	// Layar pembuka: judul besar sekali, lalu langsung hilang begitu ada
	// tombol. Menahannya tidak menambah informasi apa pun.
	if m.intro {
		return m.viewIntro()
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

// bigTitle adalah judul blok besar untuk layar pembuka. Lebarnya dibatasi
// supaya muat di terminal sempit — di HP 56 kolom, judul yang terlalu lebar
// justru terpotong jadi tidak terbaca.
var bigTitle = []string{
	"██╗      ██╗   ██╗███╗   ███╗███████╗███╗   ██╗",
	"██║      ██║   ██║████╗ ████║██╔════╝████╗  ██║",
	"██║      ██║   ██║██╔████╔██║█████╗  ██╔██╗ ██║",
	"██║      ██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║",
	"███████╗ ╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║",
	"╚══════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝",
}

// smallTitle adalah judul blok untuk terminal sempit. Lebar 22 kolom,
// supaya masih terbaca di HP 40 kolom.
var smallTitle = []string{
	"█▛▀▜█ █▛▀█ █▀█▖▛▀▖█▛▀▖▛",
	"█ ▀ █ █ █ ▀▄▖▀▀▄▖█▄▀▄▖█",
	"█   █ █▄▄▄▄▀█▄▄▀█ █  █",
	"▀   ▀ ▀▀▀▀▀▀▀ ▀▀▀ ▀  ▀",
}

// gArrow dipakai sebagai pemisah ringkas di dalam TUI. Glyph global milik
// report.go ada di dalam fungsi, jadi TUI punya konstantanya sendiri.
const gArrow = "→"

func (m *TUIModel) viewIntro() string {
	art := bigTitle
	if m.width < 46 {
		art = smallTitle
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, ln := range art {
		b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(cBrand).Render(" "+ln) + "\n")
	}
	b.WriteString("\n")
	tag := Tagline + "  " + gArrow + "  by " + Author
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).Render(tag) + "\n\n")

	if m.phase == PhaseDone && m.rep != nil {
		n := fmt.Sprintf("%d halaman  %s  %d endpoint", len(m.rep.Pages), gArrow, len(m.rep.Endpoints))
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cAccent).Render(n) + "\n\n")
	}
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cDim).
		Render("↓ atau enter untuk membuka dashboard") + "\n")
	w := m.contentWidth()
	if w < 24 {
		w = 24
	}
	return stBorder.Width(w-2).Padding(0, 1).Render(b.String())
}

// viewRootError menampilkan kegagalan pengambilan halaman awal beserta
// diagnosis yang bisa langsung dicoba.
func (m *TUIModel) viewRootError() string {
	var b strings.Builder
	b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Foreground(cHigh).
		Render("GAGAL SCAN — halaman tidak bisa diambil") + "\n\n")
	for _, ln := range wrapN(m.rep.RootError, m.contentWidth()-6) {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(cText).Render(ln) + "\n")
	}
	b.WriteString("\n  " + stDim.Render(m.target) + "\n\n")

	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Foreground(cMedium).
		Render("kemungkinan penyebab") + "\n")
	for _, h := range diagnose(m.rep.RootError) {
		// Baris lanjutan harus memakai indent yang sama dengan baris
		// pertama; kalau tidak, teksnya terlihat keluar dari daftar.
		for i, ln := range wrapN("· "+h, m.contentWidth()-10) {
			if i == 0 {
				b.WriteString("     " + stDim.Render(ln) + "\n")
			} else {
				b.WriteString("       " + stDim.Render(ln) + "\n")
			}
		}
	}
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Foreground(cLow).Render("r") +
		stDim.Render(" coba lagi   ") +
		lipgloss.NewStyle().Foreground(cAccent).Render("q") +
		stDim.Render(" keluar"))
	b.WriteString("\n")
	b.WriteString("  " + stDim.Render("laporan tetap ditulis ke out/ supaya bisa dikirim ke siapa pun yang perlu melihat"))

	w := m.contentWidth()
	if w < 30 {
		w = 30
	}
	return stBorderHi.Width(w-2).Padding(0, 1).Render(b.String())
}

// diagnose mengubah pesan error jaringan menjadi langkah yang bisa dicoba.
//
// Setiap-butir memetakan pesan yang memang dihasilkan net/http ke penyebab
// yang paling sering. Diagnosa paling penting adalah yang paling sering
// disalahdamar: DNS yang mengembalikan alamat loopback bukan berarti server
// mati, dan mengira begitu membuat orang mengejar masalah yang salah.
func diagnose(msg string) []string {
	m := strings.ToLower(msg)
	var out []string

	// Kasus "DNS diblokir": Android dan beberapa VPN mengembalikan 127.0.0.1
	// atau ::1 untuk domain yang diblokir, lalu koneksinya ditolak. Pesannya
	// terlihat seperti "server menolak koneksi", padahal tidak ada yang pernah
	// sampai ke server.
	if ip := addrInError(msg); isLoopback(ip) {
		return []string{
			"DNS mengembalikan " + ip + " (loopback) — domain ini diblokir di sisi perangkat, bukan server mati",
			"cek Android: Settings → Network → Private DNS → dimatikan atausetel Automatic",
			"cek juga daftar blokir DNS, adblock, atau VPN yang aktif",
			"scan dari jaringan lain untuk memastikan: kalau di sana berhasil, masalahnya perangkat ini",
		}
	}

	switch {
	case strings.Contains(m, "no such host"), strings.Contains(m, "dns"):
		out = append(out, "DNS tidak resolve — cek nama domain dan koneksi internet")
	case strings.Contains(m, "i/o timeout"), strings.Contains(m, "timeout"),
		strings.Contains(m, "context deadline"):
		out = append(out, "timeout — naikkan dengan -timeout 5m, atau kurangi beban jaringan")
		out = append(out, "kalau di HP, ganti jaringan: Wi-Fi captive portal sering memblokir")
	case strings.Contains(m, "connection refused"):
		out = append(out, "koneksi ditolak di alamat tujuan — cek apakah server hidup dan port terbuka")
	case strings.Contains(m, "certificate"), strings.Contains(m, "x509"), strings.Contains(m, "tls"):
		out = append(out, "sertifikat TLS bermasalah — cek tanggal berlaku dan kecocokan hostname")
	case strings.Contains(m, "network is unreachable"), strings.Contains(m, "unreachable"):
		out = append(out, "tidak ada rute ke host — cek VPN dan jaringan")
	case strings.Contains(m, "no route to host"):
		out = append(out, "tidak ada rute ke host — cek VPN dan jaringan")
	}
	out = append(out, "bisa juga salah ketik URL, atau target memang butuh autentikasi")
	return out
}

// addrInError mengambil alamat IP yang disebut di pesan error.
//
// Format yang keluaran Go:
//
//	dial tcp 1.2.3.4:443: connect: connection refused
//	dial tcp: lookup host on [::1]:42773: read: connection refused
//
// Bentuk keduanya harus ditangani; hanya yang kedua yang muncul di Android.
func addrInError(msg string) string {
	// Bentuk "[::1]:42773" atau "[1.2.3.4]:443"
	if i := strings.Index(msg, " on ["); i >= 0 {
		rest := msg[i+len(" on ["):]
		if j := strings.IndexByte(rest, ']'); j > 0 {
			return rest[:j]
		}
	}
	// Bentuk "dial tcp 1.2.3.4:443" — IPv4 tanpa kurung siku.
	if i := strings.Index(msg, "dial tcp "); i >= 0 {
		rest := msg[i+len("dial tcp "):]
		end := strings.IndexAny(rest, ": ")
		if end > 0 {
			cand := rest[:end]
			if isIPv4(cand) {
				return cand
			}
		}
	}
	// Bentuk "dial tcp [::1]:443" — IPv6 selalu ditulis dengan kurung siku.
	if i := strings.Index(msg, "["); i >= 0 {
		rest := msg[i+1:]
		if j := strings.IndexByte(rest, ']'); j > 0 {
			if cand := rest[:j]; strings.Contains(cand, ":") || isIPv4(cand) {
				return cand
			}
		}
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// isLoopback mengenali alamat yang mengarah ke perangkat sendiri.
func isLoopback(ip string) bool {
	if ip == "" {
		return false
	}
	if ip == "::1" || ip == "0:0:0:0:0:0:0:1" {
		return true
	}
	// 127.0.0.0/8
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	// "localhost" kadang muncul langsung di pesan error
	return strings.EqualFold(ip, "localhost")
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

package lumen

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// TUI berbasis Bubble Tea.
//
// Batas penting yang dijaga di sini: pemetaan permukaan adalah pekerjaan
// jaringan yang bisa memakan puluhan detik, jadi tidak boleh dijalankan
// di dalam loop render. Pemindaian berjalan di goroutine danprogress-nya
// dikirim balik lewat tea.Msg. Kalau tidak, tampilan akan membeku dan
// pengguna akan menyimpulkan tool ini hang.
//
// Panel dan navigasi:
//	↑ / k        pindah fokus ke panel di atas
//	↓ / j        pindah fokus ke panel di bawah
//	tab / shift+tab  geser fokus ke samping (opsional, untuk将来需要的)
//	pgup / pgdn  gulung isi panel
//	home / end   ke atas / bawah isi panel
//	r            scan ulang
//	q / ctrl+c   keluar
//	?            bantuan

// Panel adalah salah satu bagian dari dashboard.
type Panel struct {
	Key   string
	Title string
	// Render mengembalikan isi panel. maxW=max lebar yang tersedia,
	// maxH=max tinggi yang tersedia. Isi boleh lebih panjang — dipotong
	// oleh viewport.
	Render func(m *TUIModel, maxW, maxH int) string
}

var panels = []Panel{
	{Key: "ringkasan", Title: "Ringkasan", Render: renderRingkasan},
	{Key: "temuan", Title: "Temuan", Render: renderTemuan},
	{Key: "endpoint", Title: "Endpoint", Render: renderEndpoint},
	{Key: "kandidat", Title: "OWASP", Render: renderKandidat},
	{Key: "authz", Title: "Authz", Render: renderAuthz},
	{Key: "perubahan", Title: "Perubahan", Render: renderPerubahan},
	{Key: "cakupan", Title: "Cakupan", Render: renderCakupan},
}

// ── model ──────────────────────────────────────────────────────────────────

// Phase adalah tahap pemeriksaan yang sedang berjalan.
type Phase int

const (
	PhaseScanning Phase = iota
	PhaseDone
	PhaseFailed
)

// ScanMsg dikirim dari goroutine pemetaan ke loop TUI.
type ScanMsg struct {
	Phase Phase
	Rep   *Report
	Authz []AuthzReport
	Err   error
	// Progress ditulis saat pemetaan masih berjalan.
	Pages int
	Depth int
	Note  string
}

// TickMsg membuat TUI tetap hidup saat pemetaan berjalan lama, supaya
// spinner-nya bergerak dan pengguna tidak mengira prosesnya mati.
type TickMsg struct{}

// TUIModel adalah seluruh state TUI.
type TUIModel struct {
	rep   *Report
	cands []Candidate
	cov   Coverage
	authz []AuthzReport
	// diff menyimpan perbandingan dengan scan sebelumnya. Nil berarti
	// belum ada baseline — panel harus mengatakannya, bukan menampilkan ruang kosong.
	diff   *DiffResults
	target string

	phase Phase
	note  string
	err   error
	pages int
	tick  int
	quit  bool

	focus  int
	scroll map[string]int
	// intro mengendalikan layar pembuka. Dimunculkan sekali di awal supaya
	// ada nama dan konteks yang jelas sebelum isi dashboard mengalir.
	intro bool

	width, height int
	compact       bool
	showHelp      bool

	// Runner dipakai untuk scan ulang saat user menekan r.
	Runner func() (*Report, []AuthzReport, error)
}

func NewTUIModel(target string) *TUIModel {
	return &TUIModel{
		target: target,
		phase:  PhaseScanning,
		scroll: map[string]int{},
		tick:   0,
	}
}

// SetDiff memasang perbandingan dengan scan sebelumnya.
//
// Diff hanya bisa_INSTALL setelah panel sudah ada; pemanggil yang tahu store
// yang harus menyediakannya.
func (m *TUIModel) SetDiff(d *DiffResults) { m.diff = d }

// SkipIntro mematikan layar pembuka untuk laporan yang dimuat dari disk.
//
// Report yang sudah pernah dilihat tidak butuh perkenalan lagi; memunculkan
// judul besar di atas laporan lama hanya menambah satu keystroke sebelum isi.
func (m *TUIModel) SkipIntro() { m.intro = false }

// SetRunner memasang fungsi yang dipakai untuk menjalankan pemetaan ulang.
func (m *TUIModel) SetRunner(f func() (*Report, []AuthzReport, error)) { m.Runner = f }

// Seed mengisi model dengan hasil pemetaan yang sudah selesai.
//
// TUI dipakai setelah pemetaan selesai, bukan menggantikannya: pemetaan
// butuh jeda antar-request supaya tidak membebani server, dan itu tidak
// bisa berjalan di dalam loop render yang berjalan 60 kali per detik.
func (m *TUIModel) Seed(rep *Report, cands []Candidate, cov Coverage, authz []AuthzReport) {
	m.rep = rep
	m.cands = cands
	m.cov = cov
	m.authz = authz
	if rep != nil {
		m.target = rep.Target
	}
	m.phase = PhaseDone
	m.intro = true
}

func (m *TUIModel) Init() tea.Cmd {
	// Kalau model sudah diisi lewat Seed, pemetaan SUDAH selesai sebelum
	// TUI dibuka. Menjalankan scan lagi di sini berarti setiap request
	// ke server dilakukan dua kali — sia-sia, dan untuk server milik
	// sendiri itu beban yang tidak perlu importation.
	if m.phase == PhaseDone {
		return nil
	}
	return tea.Batch(tickCmd(), waitForScan(m.Runner))
}

func tickCmd() tea.Cmd {
	return tea.Tick(120_000_000, func(t time.Time) tea.Msg { return TickMsg{} })
}

// waitForScan menjalankan pemetaan di luar loop render.
//
// Fungsi ini hanya boleh dipanggil dari goroutine tea, bukan langsung dari
// Init/Update, supaya pemetaan tidak memblokir tampilan.
func waitForScan(run func() (*Report, []AuthzReport, error)) tea.Cmd {
	if run == nil {
		return nil
	}
	return func() tea.Msg {
		rep, az, err := run()
		return ScanMsg{Phase: PhaseDone, Rep: rep, Authz: az, Err: err}
	}
}

// ── update ─────────────────────────────────────────────────────────────────

func (m *TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.compact = msg.Width < 72
		m.resize()
		return m, nil

	case TickMsg:
		m.tick++
		if m.phase == PhaseScanning {
			return m, tickCmd()
		}
		return m, nil

	case ScanMsg:
		m.phase = msg.Phase
		m.err = msg.Err
		if msg.Rep != nil {
			m.rep = msg.Rep
			m.cands = msg.Rep.Candidates
			m.cov = msg.Rep.Coverage
			m.target = msg.Rep.Target
		}
		m.authz = msg.Authz
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *TUIModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Tombol apa pun menutup layar pembuka — kecuali "q", yang tetap keluar.
	// Menahan pembuka sampai user menekan tombol tertentu hanya menambah
	// satu langkah tanpa manfaat.
	if m.intro && msg.String() != "ctrl+c" && msg.String() != "q" {
		m.intro = false
	}

	// Pintasan global.
	switch msg.String() {
	case "ctrl+c", "q":
		m.quit = true
		return m, tea.Quit
	case "?":
		m.showHelp = !m.showHelp
		return m, nil
	}

	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	// Saat pemetaan sedang jalan, satu-satunya yang boleh dilakukan adalah
	// keluar. Menerima input lain di tengah scan hanya memberi ilusi
	// kendali atas sesuatu yang belum selesai.
	if m.phase != PhaseDone {
		return m, nil
	}

	cur := panels[m.focus].Key
	maxLines := m.contentHeight()

	switch msg.String() {
	case "up", "k":
		if m.scroll[cur] > 0 {
			m.scroll[cur]--
		} else if m.focus > 0 {
			m.focus--
		}
		return m, nil
	case "down", "j":
		if m.scroll[cur] < m.maxScroll(cur, maxLines) {
			m.scroll[cur]++
		} else if m.focus < len(panels)-1 {
			m.focus++
		}
		return m, nil
	case "pgup":
		m.scroll[cur] -= maxLines / 2
		m.clampScroll(cur, maxLines)
		return m, nil
	case "pgdown":
		m.scroll[cur] += maxLines / 2
		m.clampScroll(cur, maxLines)
		return m, nil
	case "home", "g":
		m.scroll[cur] = 0
		return m, nil
	case "end", "G":
		m.scroll[cur] = m.maxScroll(cur, maxLines)
		return m, nil
	case "tab":
		m.focus = (m.focus + 1) % len(panels)
		return m, nil
	case "shift+tab":
		m.focus = (m.focus - 1 + len(panels)) % len(panels)
		return m, nil
	case "r":
		if m.Runner != nil {
			m.phase = PhaseScanning
			m.note = "memindai ulang"
			m.rep = nil
			m.err = nil
			return m, tea.Batch(tickCmd(), waitForScan(m.Runner))
		}
		return m, nil
	}
	return m, nil
}

func (m *TUIModel) maxScroll(key string, visible int) int {
	body := panels[m.focus].Render(m, m.contentWidth(), 1000)
	n := len(strings.Split(body, "\n"))
	if n <= visible {
		return 0
	}
	return n - visible
}

func (m *TUIModel) clampScroll(key string, visible int) {
	hi := m.maxScroll(key, visible)
	if s := m.scroll[key]; s > hi {
		m.scroll[key] = hi
	}
	if m.scroll[key] < 0 {
		m.scroll[key] = 0
	}
}

// resize tidak melakukan apa-apa pada state: ukuran dipakai langsung saat
// render. Ada supaya pemanggil punya titik masuk yang jelas kalau nanti
// perlu cache layout.
func (m *TUIModel) resize() {}

// contentWidth adalah lebar area konten setelah dikurangi rail navigasi.
func (m *TUIModel) contentWidth() int {
	w := m.width - 4
	if !m.compact {
		w -= railWidth
	}
	if w < 20 {
		w = 20
	}
	return w
}

// contentHeight adalah tinggi area konten setelah dikurangi header dan footer.
func (m *TUIModel) contentHeight() int {
	h := m.height - headerHeight - footerHeight - 1
	if h < 3 {
		h = 3
	}
	return h
}

func (m *TUIModel) Quit() bool { return m.quit }

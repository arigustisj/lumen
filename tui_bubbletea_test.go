package lumen

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// mkn_model membangun model dengan isi laporan yang sudah jadi, supaya
// test fokus pada perilaku tampilan dan navigasi, bukan pada jaringan.
func testModel(t *testing.T, w, h int) *TUIModel {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/desa_wisata":
			fmt.Fprint(rw, `{"items":[]}`)
		case "/api/public/info":
			fmt.Fprint(rw, `{"app":"x"}`)
		default:
			fmt.Fprint(rw, `{"ok":true}`)
		}
	}))
	t.Cleanup(srv.Close)

	eps := []Endpoint{
		{Path: "/admin/desa_wisata", Method: "GET", Origin: OriginJS},
		{Path: "/admin/desa_wisata/${e}/status", Method: "PATCH", Origin: OriginJS},
		{Path: "/api/public/info", Method: "GET", Origin: OriginHTML},
		{Path: "/api/user/profile", Method: "GET", Origin: OriginJS},
	}
	findings := []Finding{
		{Kind: "header", Severity: SevHigh, Where: "/", Detail: "CSP tidak ada"},
		{Kind: "endpoint", Severity: SevMedium, Where: "/admin/x", Detail: "PATCH terbuka"},
	}
	ar, _ := RunAuthz(context.Background(),
		Target{Name: "uji", URL: srv.URL, Tokens: Tokens{"anon": "", "as_user_a": "Bearer t"}}.HTTPClient(),
		Target{Name: "uji", URL: srv.URL, Tokens: Tokens{"anon": "", "as_user_a": "Bearer t"}},
		eps, AuthzOptions{Baseline: "anon", Compare: []string{"as_user_a"}})

	rep := &Report{
		Target: srv.URL, DurationMS: 1234, Pages: []Page{{URL: srv.URL}},
		Endpoints: eps, Findings: findings,
		Stats: map[string]int{"pages": 1}, Authz: &ar,
	}
	m := NewTUIModel(srv.URL)
	m.Seed(rep, nil, BuildCoverage(*rep), []AuthzReport{ar})
	mm, _ := m.Update(tea.WindowSizeMsg{Width: w, Height: h})
	return mm.(*TUIModel)
}

func send(m *TUIModel, keys ...string) *TUIModel {
	for _, k := range keys {
		mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		m = mm.(*TUIModel)
	}
	return m
}

func special(m *TUIModel, msg tea.KeyMsg) *TUIModel {
	mm, _ := m.Update(msg)
	return mm.(*TUIModel)
}

// TestTUIPanelNavigasiPanah — fokus harus bergerak ke panel di bawah dan
// kembali ke atas, lalu tidak keluar dari rentang.
func TestTUIPanelNavigasiPanah(t *testing.T) {
	m := testModel(t, 100, 30)
	if m.focus != 0 {
		t.Fatalf("fokus awal = %d, mau 0", m.focus)
	}
	m = special(m, tea.KeyMsg{Type: tea.KeyDown})
	if m.focus != 1 {
		t.Errorf("setelah ↓ fokus = %d, mau 1", m.focus)
	}
	m = special(m, tea.KeyMsg{Type: tea.KeyUp})
	if m.focus != 0 {
		t.Errorf("setelah ↑ fokus = %d, mau 0", m.focus)
	}
	// Di panel paling atas, ↑ tidak boleh keluar dari rentang.
	m = special(m, tea.KeyMsg{Type: tea.KeyUp})
	if m.focus != 0 {
		t.Errorf("↑ di panel teratas = %d, harus tetap 0", m.focus)
	}
}

// TestTUITabMemutarPanel — tab harus berputar, bukan berhenti di akhir.
func TestTUITabMemutarPanel(t *testing.T) {
	m := testModel(t, 100, 30)
	last := len(panels) - 1
	m.focus = last
	m = special(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 0 {
		t.Errorf("tab dari panel terakhir = %d, mau 0 (harus berputar)", m.focus)
	}
	m = special(m, tea.KeyMsg{Type: tea.KeyShiftTab})
	if m.focus != last {
		t.Errorf("shift+tab dari panel 0 = %d, mau %d", m.focus, last)
	}
}

// TestTUIGulirTidakMelewatiBatas — scroll harus berhenti, tidak boleh
// menghasilkan offset negatif atau melebihi isi.
func TestTUIGulirTidakMelewatiBatas(t *testing.T) {
	m := testModel(t, 100, 20)
	for i := 0; i < 50; i++ {
		m = special(m, tea.KeyMsg{Type: tea.KeyPgDown})
	}
	if m.scroll["ringkasan"] < 0 {
		t.Errorf("scroll negatif: %d", m.scroll["ringkasan"])
	}
	m = special(m, tea.KeyMsg{Type: tea.KeyHome})
	if m.scroll["ringkasan"] != 0 {
		t.Errorf("home tidak mengembalikan scroll ke 0: %d", m.scroll["ringkasan"])
	}
}

// TestTUIPanelLengkapTampil — tiap panel harus menghasilkan isi yang
// tidak kosong dan memuat hal yang diharapkan.
func TestTUIPanelLengkapTampil(t *testing.T) {
	m := testModel(t, 110, 30)
	want := map[string]string{
		"ringkasan": "target",
		"temuan":    "CSP",
		"endpoint":  "/admin/desa_wisata",
		"kandidat":  "kandidat",
		"authz":     "diuji",
		"cakupan":   "diuji",
	}
	for i, p := range panels {
		m.focus = i
		out := p.Render(m, 100, 30)
		if strings.TrimSpace(out) == "" {
			t.Errorf("panel %q kosong", p.Title)
		}
		if needle := want[p.Key]; !strings.Contains(out, needle) {
			t.Errorf("panel %q tidak memuat %q", p.Title, needle)
		}
	}
}

// TestTUIQuaKeluar — q harus menghentikan program.
func TestTUIQuaKeluar(t *testing.T) {
	m := testModel(t, 100, 30)
	mm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := mm.(*TUIModel)
	if !got.Quit() {
		t.Error("q harus menandai model keluar")
	}
	if cmd == nil {
		t.Error("q harus mengembalikan tea.Quit")
	}
}

// TestTUIBantuanToggle — ? menampilkan bantuan lalu menutupnya lagi.
func TestTUIBantuanToggle(t *testing.T) {
	m := testModel(t, 100, 30)
	m = special(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	if !m.showHelp {
		t.Fatal("? harus menampilkan bantuan")
	}
	if !strings.Contains(m.View(), "Pintasan") {
		t.Error("bantuan tidak menampilkan judul")
	}
	m = special(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	if m.showHelp {
		t.Error("? kedua harus menutup bantuan")
	}
}

// TestTUIMenempelDiLebarTerminal — View tidak boleh lebih lebar dari
// terminal. Ini yang merusak tampilan kalau terminal dikecilkan.
func TestTUIMenempelDiLebarTerminal(t *testing.T) {
	for _, w := range []int{120, 100, 80, 72, 56, 40} {
		m := testModel(t, w, 30)
		for i := range panels {
			m.focus = i
			for _, line := range strings.Split(m.View(), "\n") {
				// Diukur dengan lebar tampilan, bukan byte: "↑↓" butuh
				// 6 byte tapi hanya 2 kolom.
				if n := lipgloss.Width(line); n > w+2 {
					t.Errorf("lebar %d: baris %d kolom melewati terminal:\n%q", w, n, line)
					break
				}
			}
		}
	}
}

// TestTUIMenempelSaatGulir — isi panjang harus tetap muat setelah digulir.
func TestTUIMenempelSaatGulir(t *testing.T) {
	m := testModel(t, 90, 20)
	m.focus = 2 // endpoint
	for i := 0; i < 6; i++ {
		m = special(m, tea.KeyMsg{Type: tea.KeyPgDown})
	}
	for _, line := range strings.Split(m.View(), "\n") {
		if n := lipgloss.Width(line); n > 92 {
			t.Errorf("baris %d kolom: %q", n, line)
		}
	}
}

// TestTUISelamaScanHanyaBisaKeluar — saat pemetaan berjalan, navigasi
// harus dinonaktifkan. Menerima input saat scan memberi ilusi kendali
// atas sesuatu yang belum selesai.
func TestTUISelamaScanHanyaBisaKeluar(t *testing.T) {
	m := NewTUIModel("https://x.test")
	mm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = mm.(*TUIModel)

	m = special(m, tea.KeyMsg{Type: tea.KeyDown})
	if m.focus != 0 {
		t.Error(" navigasi harus mati saat memindai")
	}
	out := m.View()
	if !strings.Contains(out, "memetakan") {
		t.Errorf("tampilan harus menunjukkan status memindai, dapat: %q", out)
	}
	// q harus tetap berfungsi.
	mm2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if !mm2.(*TUIModel).Quit() {
		t.Error("q harus tetap bisa keluar saat memindai")
	}
}

// TestTUITickMenjagaTampilanHidup — spinner harus terus berjalan selama
// pemetaan, supaya yang sedang menunggu tahu prosesnya tidak mati.
func TestTUITickMenjagaTampilanHidup(t *testing.T) {
	m := NewTUIModel("https://x.test")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	first := m.View()
	mm, cmd := m.Update(TickMsg{})
	if cmd == nil {
		t.Error("TickMsg selama scan harus menjadwalkan tick berikutnya")
	}
	m = mm.(*TUIModel)
	if m.View() == first {
		t.Error("tampilan harus berubah setelah tick (spinner)")
	}
}

// TestTUIAuthzKosongMemberiPetunjuk — panel authz harus menjelaskan
// ASSWORDnya.bib cara mengaktifkannya, bukan menampilkan layar kosong.
func TestTUIAuthzKosongMemberiPetunjuk(t *testing.T) {
	m := testModel(t, 100, 30)
	m.authz = nil
	m.focus = 4
	out := panels[m.focus].Render(m, 100, 30)
	if !strings.Contains(out, "-config") {
		t.Errorf("panel authz harus memberi petunjuk cara mengaktifkan, dapat: %q", out)
	}
}

// TestTUIPanelAuthzMenampilkanVonis — panel authz harus menampilkan path
// yang bermasalah beserta bukti per perspektif.
func TestTUIPanelAuthzMenampilkanVonis(t *testing.T) {
	m := testModel(t, 110, 30)
	m.focus = 4
	out := panels[m.focus].Render(m, 110, 30)
	if !strings.Contains(out, "/admin/desa_wisata") {
		t.Errorf("panel authz harus menampilkan path bermasalah, dapat: %q", out)
	}
	if !strings.Contains(out, "anon=") {
		t.Errorf("panel authz harus menampilkan bukti per perspektif, dapat: %q", out)
	}
}

// TestTUIRailMenampilkanJumlahIsi — navigasi harus informatif sebelum
// user mengalaminya, bukan daftar panel kosong.
func TestTUIRailMenampilkanJumlahIsi(t *testing.T) {
	m := testModel(t, 100, 30)
	rail := m.viewRail()
	if !strings.Contains(rail, "Temuan") || !strings.Contains(rail, "Endpoint") {
		t.Errorf("rail harus memuat nama panel: %q", rail)
	}
	if !strings.Contains(rail, "2") {
		t.Errorf("rail harus menunjukkan jumlah isi: %q", rail)
	}
}

// TestTUIRepanBaruSetelahScanSelesai — panel harus pindah ke isi baru.
func TestTUIRepanBaruSetelahScanSelesai(t *testing.T) {
	m := NewTUIModel("https://x.test")
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	rep := &Report{Target: "https://x.test", Endpoints: []Endpoint{{Path: "/baru", Method: "GET"}}}
	m.Update(ScanMsg{Phase: PhaseDone, Rep: rep})
	if m.phase != PhaseDone {
		t.Error("phase harus jadi done")
	}
	m.focus = 2
	if !strings.Contains(panels[m.focus].Render(m, 100, 30), "/baru") {
		t.Error("panel harus menampilkan hasil scan baru")
	}
	// Setelah selesai, navigasi harus hidup lagi.
	m.focus = 0
	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if mm.(*TUIModel).focus != 1 {
		t.Errorf("navigasi harus hidup setelah scan selesai, fokus = %d", mm.(*TUIModel).focus)
	}
}

// TestTUIInitTidakMemindaiUlang — Init tidak boleh memicu pemetaan kalau
// model sudah diisi. Kalau iya, setiap request ke server terjadi dua kali.
func TestTUIInitTidakMemindaiUlang(t *testing.T) {
	rep := &Report{Target: "https://x.test", Endpoints: []Endpoint{{Path: "/a", Method: "GET"}}}
	var called int
	m := NewTUIModel(rep.Target)
	m.SetRunner(func() (*Report, []AuthzReport, error) { called++; return rep, nil, nil })
	m.Seed(rep, nil, BuildCoverage(*rep), nil)

	if cmd := m.Init(); cmd != nil {
		t.Error("Init harus mengembalikan nil saat model sudah terisi")
	}
	if called != 0 {
		t.Errorf("Runner terpanggil %d kali saat Init, harus 0", called)
	}
}

// TestTUIInitMemindaiSaatBelumTerisi — kalau belum diisi, Init harus
// benar-benar memulai pemetaan.
func TestTUIInitMemindaiSaatBelumTerisi(t *testing.T) {
	m := NewTUIModel("https://x.test")
	m.SetRunner(func() (*Report, []AuthzReport, error) { return nil, nil, nil })
	if cmd := m.Init(); cmd == nil {
		t.Error("Init harus memulai pemetaan saat model belum terisi")
	}
}

// TestTUINilaiRingkasanTidakMempel — nilai harus dipisah dari kunci.
func TestTUINilaiRingkasanTidakMempel(t *testing.T) {
	m := testModel(t, 100, 30)
	out := panels[0].Render(m, 100, 30)
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "kandidat OWASP") {
			if strings.Contains(ln, "OWASP83") || strings.Contains(ln, "OWASP0") {
				t.Errorf("nilai menempel ke kunci: %q", ln)
			}
		}
	}
}

// TestTUILayarPembukaAda lalu hilang — judul besar hanya tampil di awal.
func TestTUILayarPembukaAdaLaluHilang(t *testing.T) {
	m := testModel(t, 100, 30)
	if !m.intro {
		t.Fatal("model harus mulai dengan layar pembuka")
	}
	view := m.View()
	if !strings.Contains(view, "LUMEN") && !strings.Contains(view, "lumen") {
		t.Errorf("layar pembuka harus menampilkan judul, dapat:\n%s", view)
	}
	if !strings.Contains(view, "by 0xlzy") {
		t.Errorf("layar pembuka harus menampilkan authorship, dapat:\n%s", view)
	}
	// Tekan tombol apa saja untuk menutupnya.
	m = special(m, tea.KeyMsg{Type: tea.KeyDown})
	if m.intro {
		t.Error("tombol harus menutup layar pembuka")
	}
	if strings.Contains(m.View(), "0xlzy") {
		t.Error("judul besar tidak boleh muncul lagi setelah ditutup")
	}
}

// TestTUIScanGagalTerlihatJelas — scan yang gagal total harus tampil sebagai
// kegagalan, bukan sebagai dashboard kosong. "0 endpoint" karena tidak ada
// API sama sekali berbeda artinya dari "tidak sempat konek".
func TestTUIScanGagalTerlihatJelas(t *testing.T) {
	m := testModel(t, 100, 30)
	// intro sengaja dibiarkan true: error harus menang atas layar pembuka.
	m.intro = true
	m.rep.RootError = `Get "https://x.test": dial tcp: lookup x.test: no such host`

	view := m.View()
	if !strings.Contains(view, "GAGAL SCAN") {
		t.Errorf("harus terlihat sebagai gagal, dapat:\n%s", view)
	}
	if !strings.Contains(view, "no such host") {
		t.Error("pesan error asli harus ditampilkan, jangan disamar jadi umum")
	}
	// Harus ada langkah yang bisa dicoba, bukan cuma memberitahu gagal.
	if !strings.Contains(view, "DNS") {
		t.Errorf("diagnosis harus menyebut DNS untuk error no such host, dapat:\n%s", view)
	}
}

// TestTUITampilanKosongDenganRootErrorTidakBohong — tanpa RootError, dashboard
// kosong tetap boleh (memang tidak ada API), tapi tidak boleh mengklaim gagal.
func TestTUITampilanKosongDenganRootErrorTidakBohong(t *testing.T) {
	m := testModel(t, 100, 30)
	m.intro = false
	m.rep.RootError = ""
	view := m.View()
	if strings.Contains(view, "GAGAL SCAN") {
		t.Error("tidak ada RootError, jadi jangan menampilkan gagal")
	}
}

// TestDiagnoseMenyetapoiPenVsGejala — pesan yang sama harus menghasilkan
// langkah yang bisa dicoba.
func TestDiagnoseMenyetapoiPenVsGejala(t *testing.T) {
	cases := map[string]string{
		"no such host":                  "DNS",
		"context deadline exceeded":     "timeout",
		"connection refused":            "koneksi ditolak",
		"x509: certificate has expired": "sertifikat",
	}
	for msg, want := range cases {
		out := diagnose(msg)
		joined := strings.Join(out, " | ")
		if !strings.Contains(joined, want) {
			t.Errorf("diagnose(%q) = %v, harus memuat %q", msg, out, want)
		}
		if len(out) == 0 {
			t.Errorf("diagnose(%q) kosong — selalu ada langkah fallback", msg)
		}
	}
}

// TestDiagnoseDNSLoopback — pesan asli dari Termux di Android. DNS
// mengembalikan ::1 karena domain diblokir di perangkat. Kelihatannya seperti
// "connection refused", padahal tidak ada yang pernah sampai ke server.
func TestDiagnoseDNSLoopback(t *testing.T) {
	realistic := `Get "https://parama-stag.coba-sam.com/": dial tcp: lookup parama-stag.coba-sam.com on [::1]:42773: read: connection refused`
	out := strings.Join(diagnose(realistic), " | ")

	if !strings.Contains(out, "loopback") {
		t.Errorf("harus menyebut loopback, dapat: %s", out)
	}
	if !strings.Contains(out, "::1") {
		t.Errorf("harus menyebut alamat yang terdeteksi, dapat: %s", out)
	}
	if !strings.Contains(out, "Private DNS") {
		t.Errorf("harus memberi langkah konkret, dapat: %s", out)
	}
	// Menyarankan "server belum jalan" di sini akan menyesatkan.
	if strings.Contains(out, "server belum jalan") || strings.Contains(out, "port tertutup") {
		t.Errorf("diagnosis salah: server-nya hidup, hanya DNS di perangkat yang memblokir. %s", out)
	}
}

// TestDiagnoseLoopbackVarianBentuk — bentuk pesan Go berbeda beda tergantung
// OS dan versi. Semua harus dikenali.
func TestDiagnoseLoopbackVarianBentuk(t *testing.T) {
	variants := []string{
		`dial tcp: lookup x.test on [127.0.0.1]:53: read: connection refused`,
		`dial tcp: lookup x.test on [::1]:42773: read: connection refused`,
		`dial tcp 127.0.0.1:443: connect: connection refused`,
		`dial tcp [::1]:443: connect: connection refused`,
	}
	for _, v := range variants {
		out := strings.Join(diagnose(v), " | ")
		if !strings.Contains(out, "loopback") {
			t.Errorf("tidak dikenali sebagai loopback: %q\n  %s", v, out)
		}
	}
}

// TestDiagnoseIPAsingBukanLoopback — alamat publik yang menolak koneksi
// memang masalah server, dan harus tetap di diagnose begitu.
func TestDiagnoseIPAsingBukanLoopback(t *testing.T) {
	msg := `dial tcp 104.21.48.183:443: connect: connection refused`
	out := strings.Join(diagnose(msg), " | ")
	if strings.Contains(out, "loopback") {
		t.Errorf("IP publik salah dikira loopback: %s", out)
	}
	if !strings.Contains(out, "koneksi ditolak") {
		t.Errorf("harus tetap menyebut koneksi ditolak, dapat: %s", out)
	}
}

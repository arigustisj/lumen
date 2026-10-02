// Package tui merapikan output terminal tanpa dependency eksternal.
//
// Kenapa tulis sendiri: library TUI yang bagus (lipgloss, termenv) menarik
// rantai dependency yang tidak sepadan untuk alat seukuran ini, dan hasil
// build harus tetap berupa binary tunggal yang jalan di Termux.
//
// Prinsip: kalau output-nya bukan terminal, atau color dimatikan, semua
// dekorasi hilang dan yang tersisa isi yang bisa di-pipe ke grep/jq.
package lumen

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// ── warna ──────────────────────────────────────────────────────────────────

const (
	reset     = "\x1b[0m"
	bold      = "\x1b[1m"
	dim       = "\x1b[2m"
	italic    = "\x1b[3m"
	underline = "\x1b[4m"

	fgRed    = "\x1b[31m"
	fgGreen  = "\x1b[32m"
	fgYellow = "\x1b[33m"
	fgBlue   = "\x1b[34m"
	fgMag    = "\x1b[35m"
	fgCyan   = "\x1b[36m"
	fgGray   = "\x1b[90m"
	fgWhite  = "\x1b[37m"
)

// Glyph karakter dekoratif. Dipisah supaya mudah diganti seluruhnya.
type Glyph struct {
	TL, TR, BL, BR string // sudut
	H, V           string // garis horizontal / vertikal
	Bar            string // baris progres
	Dot            string // bullet
	Arrow          string // pemisah
}

var unicodeGlyph = Glyph{
	TL: "╭", TR: "╮", BL: "╰", BR: "╯",
	H: "─", V: "│", Bar: "█", Dot: "•", Arrow: "→",
}

var asciiGlyph = Glyph{
	TL: "+", TR: "+", BL: "+", BR: "+",
	H: "-", V: "|", Bar: "#", Dot: "*", Arrow: "->",
}

// ── mode ───────────────────────────────────────────────────────────────────

// Style menentukan Whether dekorasi diaktifkan.
type Style struct {
	Color   bool
	Unicode bool
	Width   int
	Glyph   Glyph
}

// DetectStyle menebak mode dari lingkungan terminal.
//
// Urutan pertimbangannya penting:
//  1. NO_COLOR dihormati tanpa syarat (https://no-color.org)
//  2. LUMEN_COLOR=always memaksa warna — berguna saat pipe ke less -R
//  3. Kalau stdout bukan TTY, nonaktifkan: output jadi bisa di-grep
//  4. Terminal sangat sempit (smartphone) -> mode ringkas otomatis
func DetectStyle(stdout *os.File) Style {
	w := terminalWidth(stdout)

	plain := os.Getenv("NO_COLOR") != ""
	switch os.Getenv("LUMEN_COLOR") {
	case "always":
		plain = false
	case "never", "0":
		plain = true
	}

	isTTY := isTerminal(stdout)
	color := !plain && (isTTY || os.Getenv("LUMEN_COLOR") == "always")

	// Unicode: hampir semua terminal modern bisa. Dump ke pipe tetap ASCII.
	uni := color || os.Getenv("LUMEN_UNICODE") == "1"

	if w < 40 {
		w = 40
	}
	if w > 110 {
		w = 110 // bacaan panjang jadi tidak weary di monitor lebar
	}

	s := Style{Color: color, Unicode: uni, Width: w}
	if uni {
		s.Glyph = unicodeGlyph
	} else {
		s.Glyph = asciiGlyph
	}
	return s
}

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + reset
}

func (s Style) Bold(t string) string    { return s.c(bold, t) }
func (s Style) Dim(t string) string     { return s.c(dim, t) }
func (s Style) Red(t string) string     { return s.c(fgRed, t) }
func (s Style) Green(t string) string   { return s.c(fgGreen, t) }
func (s Style) Yellow(t string) string  { return s.c(fgYellow, t) }
func (s Style) Blue(t string) string    { return s.c(fgBlue, t) }
func (s Style) Magenta(t string) string { return s.c(fgMag, t) }
func (s Style) Cyan(t string) string    { return s.c(fgCyan, t) }
func (s Style) Gray(t string) string    { return s.c(fgGray, t) }

// ── primitif layout ────────────────────────────────────────────────────────

// Truncate memotong ke lebar tertentu, menambah elipsis bila terpotong.
// Panjang dihitung berdasarkan RUNE, bukan byte: path contains non-ASCII
// akanMIDBYTE salah hitung kalau pakai len().
func (s Style) Truncate(t string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(t)
	if len(r) <= w {
		return t
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}

// Pad menambahkan spasi sampai lebar tertentu (dalam rune).
func (s Style) Pad(t string, w int) string {
	n := len([]rune(t))
	if n >= w {
		return t
	}
	return t + strings.Repeat(" ", w-n)
}

// Wrap memecah teks panjang pada batas kata, sesuai lebar yang tersedia.
func (s Style) Wrap(t string, w int) []string {
	if w <= 4 {
		return []string{s.Truncate(t, w)}
	}
	words := strings.Fields(t)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := ""
	for _, word := range words {
		cand := word
		if cur != "" {
			cand = cur + " " + word
		}
		if len([]rune(cand)) <= w {
			cur = cand
			continue
		}
		if cur != "" {
			lines = append(lines, cur)
		}
		// Satu kata lebih panjang dari lebar: potong keras.
		for len([]rune(word)) > w {
			lines = append(lines, string([]rune(word)[:w]))
			word = string([]rune(word)[w:])
		}
		cur = word
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// Rule menggambar garis horizontal selebar Style.Width.
func (s Style) Rule() string {
	return s.Gray(strings.Repeat(s.Glyph.H, s.Width))
}

// Box menggambar kotak dengan judul di tepi atas.
func (s Style) Box(title string, lines []string) string {
	g := s.Glyph
	inner := s.Width - 2

	var b strings.Builder
	top := g.TL + g.H + " " + s.Bold(title) + " "
	if n := inner - 2 - len([]rune(title)) - 2; n > 0 {
		top += s.Gray(strings.Repeat(g.H, n))
	}
	b.WriteString(s.Gray(g.TL+g.H) + " " + s.Bold(title) + " " + s.Gray(strings.Repeat(g.H, maxInt(0, inner-4-len([]rune(title))))) + s.Gray(g.TR))
	b.WriteString("\n")

	for _, ln := range lines {
		b.WriteString(s.Gray(g.V) + " " + s.Pad(s.Truncate(ln, inner-2), inner-2) + " " + s.Gray(g.V))
		b.WriteString("\n")
	}
	b.WriteString(s.Gray(g.BL + strings.Repeat(g.H, inner) + g.BR))
	return b.String()
}

// Plain mengembalikan Style tanpa warna, untuk ditulis ke file.
func Plain(unicode bool) Style {
	g := asciiGlyph
	if unicode {
		g = unicodeGlyph
	}
	return Style{Color: false, Unicode: unicode, Width: 100, Glyph: g}
}

// Bar membuat baris meter, misalnya "████████░░░░ 62%".
// Dipakai untuk komposisi temuan per severity — jauh lebih cepat dibaca
// daripada "high 2 | medium 1 | low 1 | info 41" kalau jumlahnya besar.
func (s Style) Bar(parts []Part, w int) string {
	total := 0
	for _, p := range parts {
		total += p.N
	}
	if total == 0 {
		return ""
	}
	var b strings.Builder
	used := 0
	for i, p := range parts {
		if p.N == 0 {
			continue
		}
		n := p.N * w / total
		if i == len(parts)-1 {
			n = w - used // biar persis memenuhi w
		}
		if n <= 0 {
			continue
		}
		b.WriteString(p.Colour(strings.Repeat(s.Glyph.Bar, n)))
		used += n
	}
	if used < w {
		b.WriteString(s.Gray(strings.Repeat(s.Glyph.Bar, w-used)))
	}
	return b.String()
}

// Bar2 seperti Bar, tapi setiap bagian yang tidak nol diberi lebar minimum.
//
// Tanpa ini, komposisi temuan selalu tidak terbaca: info biasanya 10-50x
// lebih banyak dari high, jadi high habis jadi satu karakter di bar 30 kolom
// dan justru menutupi informasi yang paling penting.
func (s Style) Bar2(parts []Part, w int) string {
	total := 0
	for _, p := range parts {
		total += p.N
	}
	if total == 0 {
		return ""
	}
	const minW = 2
	raw := make([]int, len(parts))
	used := 0
	shown := 0
	for i, p := range parts {
		if p.N == 0 {
			continue
		}
		shown++
		raw[i] = p.N * w / total
		if raw[i] < minW {
			raw[i] = minW
		}
		used += raw[i]
	}
	// Kalau minimum membuat total melebihi w, proporsikan ulang bagian
	// yang tidak diklem.
	if used > w && shown > 0 {
		over := used - w
		big := 0
		for i, p := range parts {
			if p.N > 0 && raw[i] > minW && raw[i] > big {
				big = raw[i]
			}
		}
		if big > 0 {
			raw[argmax(raw)] -= over
			if raw[argmax(raw)] < minW {
				raw[argmax(raw)] = minW
			}
		}
	}
	var b strings.Builder
	for i, p := range parts {
		if p.N == 0 || raw[i] <= 0 {
			continue
		}
		b.WriteString(p.Colour(strings.Repeat(s.Glyph.Bar, raw[i])))
	}
	if n := w - used; n > 0 {
		b.WriteString(s.Gray(strings.Repeat(s.Glyph.Bar, n)))
	}
	return b.String()
}

func argmax(v []int) int {
	best := 0
	for i, n := range v {
		if v[best] == 0 || n > v[best] {
			best = i
		}
	}
	return best
}

// Part adalah satu irisan di Bar.
type Part struct {
	Label  string
	N      int
	Colour func(string) string
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── deteksi terminal ───────────────────────────────────────────────────────

func isTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(tcGets),
		uintptr(unsafe.Pointer(&t)),
		0, 0, 0,
	)
	return errno == 0
}

const tcGets = 0x5401 // TIOCGWINSZ

type winsize struct {
	Row, Col, Xpixel, Ypixel uint16
}

// terminalWidth membaca lebar jendela sungguhan.
//
// Penting untuk Termux: smartphone bisa 360px dan 1080px tergantung
// orientasi dan split-screen. Menebak 80 kolom di layar 360px artinya
// setiap baris terpotong tepat di bagian yang paling penting.
func terminalWidth(f *os.File) int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n := atoi(v); n > 0 {
			return n
		}
	}
	var ws winsize
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(tcGets),
		uintptr(unsafe.Pointer(&ws)),
		0, 0, 0,
	)
	if errno == 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	return 80
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

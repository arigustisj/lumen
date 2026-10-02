// Package model mendefinisikan tipe data yang dipakai lintas package.
//
// Dipisah dari logika supaya output JSON punya satu sumber kebenaran: kalau
// field berubah di sini, semua layer ikut berubah.
package lumen

import "time"

// Brand — penanda pembuat. Dipakai di header output, -version, dan banner
// binary supaya jelas dari mana tool ini, dan supaya ada yangrostik
// accountable kalau nanti dipakai orang lain.
const (
	Name    = "lumen"
	Tagline = "pemeta permukaan aplikasi web"
	Author  = "0xlzy"
	Version = "0.8.0"
)

// Banner mengembalikan satu baris identitas, mis. "lumen 0.3.1 — pemeta
// permukaan aplikasi web · by 0xlzy".
func Banner() string {
	return Name + " " + Version + " · " + Tagline + " · by " + Author
}

// Severity adalah tingkat seriousness temuan.
type Severity string

const (
	SevHigh   Severity = "high"
	SevMedium Severity = "medium"
	SevLow    Severity = "low"
	SevInfo   Severity = "info"
)

// Finding adalah satu hal yang layak dilihat manusia. Tool ini tidak
// menyimpulkan kerentanan — dia hanya menunjuk sesuatu yang menarik.
// Penilaian tetap di tangan orang.
// Finding adalah satu temuan.
//
// Title dan Detail dipisah karena tujuannya berbeda: Title jadi baris pertama
// daftar dan judul bagian di laporan, jadi harus pendek dan bisa dibaca sekilas.
// Detail adalah penjelasannya dan boleh panjang.
//
// Memaksakan judul dari baris pertama Detail menghasilkan judul sepanjang satu
// paragraf, yang justru menutupi informasi lain di daftar.
type Finding struct {
	Title    string   `json:"title,omitempty"`
	Kind     string   `json:"kind"`
	Severity Severity `json:"severity"`
	Where    string   `json:"where"`
	Detail   string   `json:"detail"`
}

// Origin menandai dari mana endpoint ditemukan. Penting untuk confidence:
// path dari JS bundle jauh lebih reliable daripada link yang diklik navigasi.
type Origin string

const (
	OriginHTML  Origin = "html"  // dari <a href> atau <form action>
	OriginJS    Origin = "js"    // dari string di dalam bundle
	OriginProbe Origin = "probe" // hasil probing langsung
)

type Endpoint struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Origin Origin   `json:"origin"`
	Source string   `json:"source,omitempty"`
	Status int      `json:"status,omitempty"`
	Title  string   `json:"title,omitempty"`
	Flags  []string `json:"flags,omitempty"`
}

type Page struct {
	URL        string            `json:"url"`
	Status     int               `json:"status"`
	Title      string            `json:"title"`
	ContentLen int               `json:"content_len"`
	IsHTML     bool              `json:"html"`
	Headers    map[string]string `json:"headers,omitempty"`
	Cookies    []string          `json:"cookies,omitempty"`
	QueryKeys  []string          `json:"query_keys,omitempty"`
	FormFields []string          `json:"form_fields,omitempty"`
}

// Report adalah output akhir: satu file JSON yang bisa dibaca agent, diff, atau
// disimpan sebagai baseline untuk dibandingkan setelah patch.
type Report struct {
	Target      string         `json:"target"`
	GeneratedAt time.Time      `json:"generated_at"`
	DurationMS  int64          `json:"duration_ms"`
	Pages       []Page         `json:"pages"`
	Endpoints   []Endpoint     `json:"endpoints"`
	Findings    []Finding      `json:"findings"`
	ScopeDenied []string       `json:"scope_denied,omitempty"`
	Stats       map[string]int `json:"stats"`

	// Candidates adalah kandidat kerentanan berdasarkan OWASP, lengkap
	// dengan langkah verifikasi. Wajib ada di JSON — output terminal cuma
	// ringkasan, sedangkan bagian yang menentukan tindakan ada di sini.
	Candidates []Candidate `json:"candidates,omitempty"`
	// Coverage menyatakan apa yang tidak diuji. Tanpa ini, laporan kosong
	// terlihat sama dengan laporan yang bersih.
	Coverage Coverage `json:"coverage"`
	// RootError mengisi kalau halaman awal gagal diambil. Wajib ada supaya
	// laporan kosong bisa dibedakan dari laporan yang gagal.
	RootError string `json:"root_error,omitempty"`
	// DNSNote mencatat resolver mana yang dipakai. Wajib ada kalau ada
	// fallback: hasil scan yang memakai resolver berbeda tidak sepenuhnya
	// setara dengan scan memakai DNS perangkat, dan itu perlu diketahui.
	DNSNote string `json:"dns_note,omitempty"`
	// Authz menyimpan hasil perbandingan akses. Hanya ada kalau pemeriksaan
	// diferensial dijalankan.
	Authz *AuthzReport `json:"authz,omitempty"`

	// BOLA menyimpan hasil ownership substitution — bukti langsung bahwa
	// akun non-pemilik bisa membaca objek milik orang lain. Berbeda dengan
	// authz, field ini tidak pernah berisi dugaan: setiap entri di dalamnya
	// disertai respons nyata dari server.
	BOLA *OwnerReport `json:"bola,omitempty"`
}

// Package scope berisi penjaga yang WAJIB dilewati setiap request outbound.
//
// Ini bukan lapisan opsional. Tanpa batas host, pemetaan diam-diam jatuh ke
// CDN, font host, telemetri, dan domain pihak ketiga yang根本不 kita otorisasi.
// Guard di sini membuat Violasi terlihat di laporan (ScopeDenied) alih-alih
// terjadi diam-diam.
package lumen

import (
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"
)

// Scope mengizinkan hanya satu origin.
type Scope struct {
	host string
	port string

	mu     sync.Mutex
	denied map[string]int // host → berapa kali ditolak
}

func NewScope(u *url.URL) *Scope {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return &Scope{host: u.Hostname(), port: port, denied: map[string]int{}}
}

// Allows melaporkan apakah URL ini dalam scope. Jika tidak, host-nya dicatat
// supaya bisa ditampilkan di laporan sebagai bukti guard bekerja.
func (s *Scope) Allows(u *url.URL) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Hostname() == s.host {
		return true
	}
	s.denied[u.Hostname()]++
	return false
}

// Host mengembalikan host yang diizinkan — untuk pesan error yang jelas.
func (s *Scope) Host() string { return s.host }

func (s *Scope) SameHost(u *url.URL) bool { return u.Hostname() == s.host }

// Denied mengembalikan daftar host yang ditolak, terurut, supaya output stabil
// antar-run (penting supaya diff antar-scan tidak bocor oleh urutan map).
func (s *Scope) Denied() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.denied))
	for h, n := range s.denied {
		out = append(out, fmt.Sprintf("%s (ditolak %d)", h, n))
	}
	sort.Strings(out)
	return out
}

// Limiter memberi jeda minimal antar request ke host yang sama.
//
// Default sengaja konservatif. Scan yang terlalu cepat dari IP yang sama
// _rmasih milik sendiri_ tetap dapat merusak reputation IP itu kalau
// ternyata menyasar pihak ketiga — dan itu alasan klasik kenapaFindings
// yang sah dianggap abuse.
type Limiter struct {
	mu    sync.Mutex
	every time.Duration
	last  time.Time
}

func NewLimiter(every time.Duration) *Limiter {
	return &Limiter{every: every}
}

func (l *Limiter) Wait() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if d := time.Since(l.last); d < l.every {
		time.Sleep(l.every - d)
	}
	l.last = time.Now()
}

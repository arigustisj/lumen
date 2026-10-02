package lumen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNS fallback.
//
// Masalah nyata yang ditemukan dari pemakaian di Termux: Android dan
// beberapa operator memblokir domain tertentu dengan membalas alamat loopback
// (127.0.0.1 atau ::1). Gejalanya terlihat seperti server menolak koneksi,
// padahal tidak ada request yang pernah sampai ke server.
//
// Fungsi di sini membuat alat bisa melewati itu: kalau DNS sistem mengembalikan
// loopback atau gagal, coba resolver publik. Kalau salah satu berhasil, scan
// lanjut dengan resolver itu.
//
// Batasnya perlu jujur disebut: ini hanya membantu kalau blokirnya ada di
// resolver yang dipilih perangkat. Kalau jaringannya sendiri memblokir IP
// Cloudflare, tidak ada DNS yang menolong.

// publicResolvers diurutkan berdasarkan keandalan yang sering dipakai di
// jaringan rumah dan seluler.
var publicResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// DNSResult mencatat resolver mana yang dipakai dan kenapa.
type DNSResult struct {
	Host      string
	IPs       []string
	Used      string // "sistem" atau alamat resolver
	Fallback  bool   // apakah sistem gagal lalu memakai resolver publik
	SystemMsg string // pesan error dari resolver sistem, kalau ada
	Notes     []string
}

// PreflightDNS mengecek apakah host bisa di-resolve, dan mengembalikan
// resolver yang perlu dipakai.
//
// Urutannya: coba sistem dulu (paling cepat, hormati split-horizon DNS
// internal perusahaan). Kalau hasilnya loopback atau gagal, coba resolver
// publik satu per satu. Resolver pertama yang berhasil dipakai untuk scan.
func PreflightDNS(ctx context.Context, host string) (DNSResult, string) {
	res := DNSResult{Host: host}

	// 1. Resolver sistem.
	sysCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	addrs, err := net.DefaultResolver.LookupHost(sysCtx, host)
	cancel()
	if err == nil {
		if ip := firstLoopback(addrs); ip != "" {
			res.SystemMsg = "resolver sistem mengembalikan " + ip + " (loopback)"
			res.Notes = append(res.Notes,
				"domain ini diblokir oleh DNS perangkat — operasi atau adblock yang aktif")
		} else {
			res.IPs = addrs
			res.Used = "sistem"
			return res, ""
		}
	} else {
		res.SystemMsg = "resolver sistem gagal: " + firstLineOf(err.Error())
		res.Notes = append(res.Notes, "resolver sistem tidak bisa resolve host ini")
	}

	// 2. Resolver publik, satu per satu.
	var lastErr error
	for _, srv := range publicResolvers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, srv)
			},
		}
		c, c2 := context.WithTimeout(ctx, 6*time.Second)
		addrs, err := r.LookupHost(c, host)
		c2()
		if err != nil || len(addrs) == 0 {
			lastErr = err
			continue
		}
		if ip := firstLoopback(addrs); ip != "" {
			lastErr = fmt.Errorf("resolver %s juga memblokir host ini", srv)
			continue
		}
		res.IPs = addrs
		res.Used = srv
		res.Fallback = true
		res.Notes = append(res.Notes,
			"scan memakai resolver publik "+srv+" karena DNS perangkat memblokir")
		return res, ""
	}

	// Semua gagal.
	msg := res.SystemMsg
	if lastErr != nil {
		msg = "resolver sistem: " + res.SystemMsg + "; resolver publik: " + firstLineOf(lastErr.Error())
	}
	return res, msg
}

// firstLoopback mengembalikan alamat loopback pertama dalam daftar, atau
// string kosong jika tidak ada.
func firstLoopback(addrs []string) string {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.IsLoopback() {
			return a
		}
	}
	return ""
}

func firstLineOf(s string) string {
	if i := strings.IndexAny(s, "\n"); i > 0 {
		return s[:i]
	}
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// PinnedDialer mengarahkan koneksi ke host target ke IP tertentu.
//
// Dipasang sebagai DialContext milik pemetaan. Tujuannya: scan yang sudah
// lolos preflight tidak mengulang DNS di tengah jalan. Kalau tidak, resolver
// bisa mengembalikan loopback lagi di request berikutnya dan scan gagal
// separuh jalan — hasil paling menyesatkan karena kelihatan berhasil sampai
// titik itu.
//
// Hanya host target yang dipin. Aset yang menunjuk CDN atau subdomain lain
// tetap di-resolve normal; kalau semuanya dipin, pemetaan tidak bisa
// menjangkau aset yang diambil dari domain lain.
type PinnedDialer struct {
	Host string // hostname target, mis. "app.example.com"
	IP   string // IP hasil preflight; kosong = pakai DNS biasa
	Port string // port target, mis. "443"

	base *net.Dialer
}

// NewPinnedDialer membuat dialer dengan IP target yang sudah diketahui.
func NewPinnedDialer(host, ip, port string) *PinnedDialer {
	if port == "" {
		port = "443"
	}
	return &PinnedDialer{
		Host: host, IP: ip, Port: port,
		base: &net.Dialer{Timeout: 12 * time.Second, KeepAlive: 30 * time.Second},
	}
}

// DialContext mengarahkan host target ke IP yang dipin.
func (p *PinnedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.IP == "" || p.Host == "" {
		return p.base.DialContext(ctx, network, addr)
	}
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		h = addr
	}
	if !strings.EqualFold(h, p.Host) {
		return p.base.DialContext(ctx, network, addr)
	}
	return p.base.DialContext(ctx, network, net.JoinHostPort(p.IP, p.Port))
}

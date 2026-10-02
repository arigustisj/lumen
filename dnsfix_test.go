package lumen

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestPreflightMemakaiSistemKalauNormal — kalau DNS sistem sehat, tidak
// boleh ada fallback. Memakai resolver publik tanpa perlu membuang
// split-horizon DNS internal perusahaan.
func TestPreflightMemakaiSistemKalauNormal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := PreflightDNS(ctx, "example.com")
	if err != "" {
		t.Skipf("tidak ada jaringan di lingkungan test: %s", err)
	}
	if res.Used == "" {
		t.Fatalf("tidak ada resolver yang berhasil dipakai: %+v", res)
	}
	if res.Fallback {
		t.Errorf("DNS sistem normal seharusnya tidak fallback, dapat %s", res.Used)
	}
	if len(res.IPs) == 0 {
		t.Error("tidak ada IP yang dikembalikan")
	}
}

// TestPreflightGagalKalauSemuaResolverMenolak — kalau semua resolver gagal,
// pesan harus menyebut resolver sistem supaya bisaCompared dengan sistem
// miliknya sendiri.
func TestPreflightGagalKalauSemuaResolverMenolak(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := PreflightDNS(ctx, "host-yang-pastinya-tidak-ada-xyz123.invalid")
	if err == "" {
		t.Skipf("resolver publik ikut menjawab .invalid (mungkin DNS wildcard): %+v", res)
	}
	if !strings.Contains(err, "resolver") {
		t.Errorf("pesan harus menyebut resolver, dapat: %s", err)
	}
}

// TestFirstLoopbackMengenaliAlamatLoopback — ini inti dari deteksi blokir
// DNS. Android membalas 127.0.0.1 atau ::1 untuk domain yang diblokir.
func TestFirstLoopbackMengenaliAlamatLoopback(t *testing.T) {
	cases := []struct {
		addrs []string
		want  string
	}{
		{[]string{"127.0.0.1"}, "127.0.0.1"},
		{[]string{"::1"}, "::1"},
		{[]string{"0:0:0:0:0:0:0:1"}, "0:0:0:0:0:0:0:1"},
		{[]string{"104.21.48.183", "127.0.0.1"}, "127.0.0.1"},
		{[]string{"2606:4700::1", "::1"}, "::1"},
		{[]string{"104.21.48.183"}, ""},
		{[]string{"172.67.155.188", "8.8.8.8"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := firstLoopback(c.addrs); got != c.want {
			t.Errorf("firstLoopback(%v) = %q, mau %q", c.addrs, got, c.want)
		}
	}
}

// TestPinnedDialerDialKeIPYangDitetapkan — host target harus diarahkan ke IP
// yang dipin, bukan ke hasil DNS sistem.
func TestPinnedDialerDialKeIPYangDitetapkan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	host, port := hostPortOf(t, srv.URL)
	p := NewPinnedDialer(host, "127.0.0.1", port)

	client := &http.Client{Transport: &http.Transport{DialContext: p.DialContext}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("dial ke IP yang dipin gagal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, mau 200", resp.StatusCode)
	}
}

func hostPortOf(t *testing.T, raw string) (string, string) {
	t.Helper()
	s := strings.TrimPrefix(raw, "http://")
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "80"
	}
	return s[:i], s[i+1:]
}

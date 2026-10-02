// Package probe melakukan verifikasi pasif terhadap endpoint yang ditemukan
// di dalam bundle JavaScript.
//
// Batas yang disengaja: HANYA OPTIONS. Tidak ada POST, PUT, PATCH, atau
// DELETE — jadi tidak ada perubahan state di server, sekecil apa pun.
// Kalau sebuah endpoint ternyata butuh metode lain untuk diuji, itu
// keputusan manusia, bukan keputusan tool.
package probe

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"lumen/internal/extract"
	"lumen/internal/mapper"
	"lumen/internal/model"
)

// Options mengatur parameter probe.
type Options struct {
	Conc int
}

// Run memeriksa endpoint hasil ekstraksi JS dan menandai yang merespons
// tanpa autentikasi. Respons 2xx pada endpoint yang seharusnya tertutup
// adalah temuan paling berharga di seluruh alur ini, jadi diberi severity tinggi.
func Run(ctx context.Context, m *mapper.Mapper, eps []model.Endpoint, opts Options) []model.Endpoint {
	if opts.Conc < 1 {
		opts.Conc = 4
	}

	// Hanya endpoint dari bundle: path dari <a href> sudah jelas ada
	// atau tidak, dan memverifikasinya hanya menambah beban tanpa informasi baru.
	candidates := make([]model.Endpoint, 0, len(eps))
	for _, e := range eps {
		if e.Origin == model.OriginJS && e.Path != "" && strings.HasPrefix(e.Path, "/") {
			candidates = append(candidates, e)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Path < candidates[j].Path })

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Conc)
	base := m.Target()

	for _, e := range candidates {
		abs, ok := extract.AbsResolve(base.String(), e.Path)
		if !ok {
			continue
		}
		u, err := url.Parse(abs)
		if err != nil || !m.Scope().Allows(u) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(e model.Endpoint, abs string) {
			defer wg.Done()
			defer func() { <-sem }()

			m.Limiter().Wait()
			req, err := http.NewRequestWithContext(ctx, http.MethodOptions, abs, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "lumen/1.0 (authorized-security-review)")
			// Origin dikirim supaya server yang memang mengonfigurasi CORS
			// akan menjawab; tanpa ini kita tidak bisa melihat apakah
			// policy-nya longgar.
			req.Header.Set("Origin", base.Scheme+"://"+base.Host)

			client := &http.Client{
				Timeout: 15 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if !m.Scope().Allows(req.URL) {
						return http.ErrUseLastResponse
					}
					if len(via) > 3 {
						return http.ErrUseLastResponse
					}
					return nil
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

			flags := classify(resp)
			if len(flags) == 0 {
				return
			}
			mu.Lock()
			e.Status = resp.StatusCode
			e.Origin = model.OriginProbe
			e.Flags = append(e.Flags, flags...)
			mu.Unlock()
		}(e, abs)
	}
	wg.Wait()
	return candidates
}

func classify(resp *http.Response) []string {
	var flags []string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		flags = append(flags, "AKSES-TANPA-AUTH")
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		flags = append(flags, "terproteksi-auth")
	case resp.StatusCode == 405:
		flags = append(flags, "metode-tidak-diizinkan")
	}
	if acao := resp.Header.Get("Access-Control-Allow-Origin"); acao != "" {
		flags = append(flags, "cors-allow-origin="+acao)
		if resp.Header.Get("Access-Control-Allow-Credentials") == "true" {
			flags = append(flags, "cors-credentials=true")
		}
	}
	return flags
}

// Severity memberi bobot pada flag — dipakai untuk urutan laporan.
func Severity(flags []string) model.Severity {
	for _, f := range flags {
		if strings.Contains(f, "AKSES-TANPA-AUTH") || strings.HasPrefix(f, "cors-") {
			return model.SevHigh
		}
	}
	return model.SevInfo
}

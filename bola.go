package lumen

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bukti BOLA lewat ownership substitution.
//
// ---------------------------------------------------------------------
// Kenapa "dicurigai" tidak cukup
// ---------------------------------------------------------------------
//
// Authz differential versi lama menyimpulkan "bola-dicurigai" ketika dua
// akun sah mendapat 200 dengan isi berbeda pada endpoint berparameter objek.
// Itu benar, tapi tidak dapat dibantah: data yang berbeda antar-user adalah
// hal yang wajar pada endpoint publik. Tidak ada pembaca laporan yang bisa
// membedakan "kebocoran" dari "memang begitu" hanya dari bukti itu.
//
// Bukti yang sebenarnya tidak memerlukan tebakan sama sekali:
//
//	1. Masuk sebagai akun PEMILIK. Buka endpoint daftar miliknya.
//	2. Kumpulkan ID objek yang benar-benar milik dia.
//	3. Request ID itu memakai token akun LAIN.
//
// Kalau langkah 3 mengembalikan 200 dengan body yang sama persis dengan yang
// dilihat pemiliknya di langkah 1, maka akun lain membaca data privat
// orang tersebut. Itu bukan dugaan: itu data milik A yang keluar lewat
// kredensial B.
//
// Kalau langkah 3 mengembalikan 403 atau 404, guard-nya bekerja dan tool
// mencatatnya sebagai aman — bukan "tidak ditemukan", yang akan disalahartikan
// sebagai celah.
//
// ---------------------------------------------------------------------
// Batasnya, dan itu batas yang jujur
// ---------------------------------------------------------------------
//
// Metode ini hanya bisa membuktikan kebocoran yang involves objek milik akun
// yang memang dipakai sebagai sumber. Ia tidak menemukan:
//   - ID yang tidak muncul di daftar (mis. objek lama yang di-paginate)
//   - Endpoint tanpa daftar pembuka
//   - Objek milik orang yang tidak punya akun uji
//
// Kegagalan menemukan BOLA di sini berarti "tidak terbukti pada cakupan ini",
// bukan "aman". Laporan menyatakan itu.

// OwnerVerdict adalah hasil satu uji ownership substitution.
type OwnerVerdict string

const (
	// OwnerLeak: akun non-pemilik membaca objek milik orang lain. Terbukti.
	OwnerLeak OwnerVerdict = "bocor-terbukti"
	// OwnerGuarded: server menolak. Guard bekerja.
	OwnerGuarded OwnerVerdict = "terjaga"
	// OwnerUnknown: server menjawab lain yang tidak bisa ditafsirkan.
	OwnerUnknown OwnerVerdict = "tidak-terbaca"
)

// OwnerSwap adalah satu bukti lengkap, dari ID asal sampai verdictnya.
type OwnerSwap struct {
	ObjectID  string
	ListPath  string
	Owner     string
	Intruder  string
	OwnerCode int
	OwnerHash string
	SwapCode  int
	SwapHash  string
	Verdict   OwnerVerdict
	Note      string
}

// OwnerReport merangkai seluruh uji untuk satu target.
type OwnerReport struct {
	Target     string
	Pairs      []string // pasangan akun yang diuji
	ListsUsed  []string
	Swaps      []OwnerSwap
	Proven     int
	Guarded    int
	Unreadable int
	// Coverage menyatakan kenapa pengujian bisa tidak lengkap.
	Coverage string
}

// idFieldRe menangkap field id di body JSON pada level berapa pun.
//
// Sengaja longgar: bentuk {"data":{"items":[{"OrderId":12}]}} harus tetap
// tertangkap, karena itu yang routinely dikirim API sungguhan.
var idFieldRe = regexp.MustCompile(`(?i)"([a-z_]*(?:^|[a-z])_?id)"\s*:\s*"?([0-9]{1,15}|[0-9a-fA-F-]{32,36})"?`)

// collectIDs mengambil nilai field id dari body JSON.
//
// Non-JSON sengaja menghasilkan nol hasil. Endpoint yang mengembalikan HTML
// tidak punya "daftar objek milik aku", dan memaksakan tebakan darinya hanya
// menghasilkan noise.
func collectIDs(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string

	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if isIDKey(k) {
					if s, ok := idValue(val); ok && !seen[s] {
						seen[s] = true
						out = append(out, s)
					}
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	sort.Strings(out)
	return out
}

func isIDKey(k string) bool {
	l := strings.ToLower(strings.ReplaceAll(k, "_", ""))
	return l == "id" || strings.HasSuffix(l, "id") || strings.HasSuffix(l, "uuid")
}

func idValue(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return "", false
		}
		return t, true
	case float64:
		// ID numerik harus bilangan bulat dan tidak seperti JSON value
		// biasa (harga, timestamp, koordinat). ID biasanya bulat dan wajar.
		if t == float64(int64(t)) && t > 0 && t < 1e15 {
			return strconv.FormatInt(int64(t), 10), true
		}
	case json.Number:
		return t.String(), true
	}
	return "", false
}

// ProbeOwnership menjalankan uji ownership substitution untuk satu target.
//
// compare harus berisi minimal dua akun sah (tanpa "anon"). Endpoint daftar
// dikumpulkan dari eps — endpoint yang diumbered/ber-UUID tidak bisa dipakai
// sebagai sumber karena isinya bukan "milik aku".
func ProbeOwnership(ctx context.Context, client *http.Client, target Target,
	eps []Endpoint, owner, intruder string, delay time.Duration) OwnerReport {

	pers := []string{owner, intruder}
	cl := NewClients(target, pers, client)

	rep := OwnerReport{
		Target: target.URL,
		Pairs:  []string{owner + " -> " + intruder},
		Coverage: "Hanya objek yang muncul di daftar milik akun pemilik yang diuji. " +
			"Objek di luar daftar, endpoint tanpa daftar, dan akun tanpa akun uji tidak diperiksa.",
	}

	// Kumpulkan kandidat endpoint daftar.
	var lists []string
	for _, e := range eps {
		if e.Method != "" && e.Method != http.MethodGet {
			continue
		}
		if hasObjectParam(e.Path) || strings.Contains(e.Path, "{") {
			continue
		}
		if !isSensitivePath(e.Path) && !isLikelyCollection(e.Path) {
			continue
		}
		lists = append(lists, e.Path)
	}
	sort.Strings(lists)
	rep.ListsUsed = lists

	for _, list := range lists {
		if err := ctx.Err(); err != nil {
			return rep
		}
		sleep(delay)

		// 1. Daftar milik pemilik.
		ownerView := fetchView(ctx, cl.For(owner), target, list, owner)
		if ownerView.Error != "" || ownerView.Status < 200 || ownerView.Status >= 300 {
			continue
		}
		bodyOwner, err := fetchBody(ctx, cl.For(owner), target, list, owner)
		if err != nil {
			continue
		}
		ids := collectIDs(bodyOwner)
		if len(ids) == 0 {
			continue
		}

		// Batasi supaya tidak membanjiri server./sample Nunca lengkap,
		// dan laporan menyatakan batasnya.
		if len(ids) > 12 {
			ids = ids[:12]
		}

		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return rep
			}
			sleep(delay)

			objPath := strings.TrimSuffix(list, "/") + "/" + id
			swap := OwnerSwap{ObjectID: id, ListPath: list, Owner: owner, Intruder: intruder}

			// 2. Pemilik membaca objeknya sendiri.
			ownView := fetchView(ctx, cl.For(owner), target, objPath, owner)
			swap.OwnerCode = ownView.Status
			swap.OwnerHash = ownView.Hash
			if ownView.Status < 200 || ownView.Status >= 300 || ownView.Error != "" {
				swap.Verdict = OwnerUnknown
				swap.Note = "pemilik sendiri tidak bisa membuka objek ini; pengujian dilewati"
				rep.Unreadable++
				rep.Swaps = append(rep.Swaps, swap)
				continue
			}

			// 3. Orang lain mencoba membaca objek yang sama.
			intView := fetchView(ctx, cl.For(intruder), target, objPath, intruder)
			swap.SwapCode = intView.Status
			swap.SwapHash = intView.Hash

			switch {
			case intView.Error != "":
				swap.Verdict = OwnerUnknown
				swap.Note = "request gagal: " + intView.Error
				rep.Unreadable++

			case intView.Status == 403 || intView.Status == 401:
				swap.Verdict = OwnerGuarded
				swap.Note = fmt.Sprintf("server menolak dengan %d — guard bekerja", intView.Status)
				rep.Guarded++

			case intView.Status == 404:
				swap.Verdict = OwnerGuarded
				swap.Note = "server menyembunyikan objek (404) — guard bekerja"
				rep.Guarded++

			case intView.Status >= 200 && intView.Status < 300:
				if ownView.Hash != "" && intView.Hash == ownView.Hash {
					swap.Verdict = OwnerLeak
					swap.Note = fmt.Sprintf("%s membaca objek milik %s dan mendapat respons yang sama persis (%d) — data privat keluar lewat kredensial orang lain",
						intruder, owner, intView.Status)
					rep.Proven++
				} else {
					swap.Verdict = OwnerUnknown
					swap.Note = fmt.Sprintf("%s mendapat %d tapi body berbeda dari yang dilihat pemilik — belum tentu kebocoran, perlu dibaca manual",
						intruder, intView.Status)
					rep.Unreadable++
				}

			default:
				swap.Verdict = OwnerUnknown
				swap.Note = fmt.Sprintf("status tidak terduga %d", intView.Status)
				rep.Unreadable++
			}
			rep.Swaps = append(rep.Swaps, swap)
		}
	}
	return rep
}

func isLikelyCollection(path string) bool {
	l := strings.ToLower(path)
	for _, s := range []string{"list", "all", "index", "orders", "items", "users", "data", "cagar_budaya", "destinasi", "umkm", "event"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	time.Sleep(d)
}

// fetchBody mengambil body mentah untuk satu perspektif.
//
// Berbeda dengan fetchView, yang hanya menyimpan ringkasan, fungsi ini
// mengembalikan body apa adanya. Ini diperlukan karena yang harus dicocokkan
// adalah isi yang dilihat pemilik, bukan hash-nya sendiri — hash sudah
// dihitung ulang di tempat lain dan hanya berguna kalau kedua sisinya
// benar-benar berasal dari request yang sama.
func fetchBody(ctx context.Context, client *http.Client, target Target, path, pers string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, hv := range target.HeaderFor(pers) {
		if strings.EqualFold(k, "Cookie") {
			continue
		}
		req.Header.Set(k, hv)
	}
	req.Header.Set("Accept-Encoding", "identity")
	WithCSRF(client, req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	const limit = 2 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return normalizeBody(b), nil
}

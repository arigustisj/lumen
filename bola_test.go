package lumen

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// srvBola membangun server uji dengan perilaku yang bisa dipilih.
//
// Dipakai untuk membuktikan bahwa ProbeOwnership benar-benar membedakan
// "bocor" dari "terjaga" — bukan sekadar membaca verdict yang sudah ditulis
// sebelumnya. Kalau test ini bisa lulus dengan server yang selalu gagal,
// maka testnya tidak menguji apa pun.
type bolaServer struct {
	// guarded=true berarti server memeriksa kepemilikan dengan benar.
	guarded bool
	// owner adalah akun yang memiliki objek.
	owner string
}

func (s bolaServer) token(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func (s bolaServer) who(r *http.Request) string {
	t := s.token(r)
	if t == "" {
		return "anon"
	}
	return strings.TrimSuffix(t, "-token")
}

func (s bolaServer) handler() http.Handler {
	mux := http.NewServeMux()
	objects := map[string]map[string]any{
		"1001": {"id": 1001, "owner": "alice", "item": "laptop", "note": "PIN alice: 4417"},
		"1002": {"id": 1002, "owner": "alice", "item": "monitor", "note": "alamat alice"},
		"2001": {"id": 2001, "owner": "bob", "item": "sepatu", "note": "alamat bob"},
	}
	listOf := map[string][]int{"alice": {1001, 1002}, "bob": {2001}}

	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		u := s.who(r)
		if u == "anon" {
			http.Error(w, `{"error":"butuh login"}`, http.StatusUnauthorized)
			return
		}
		ids := listOf[u]
		if ids == nil {
			http.Error(w, `{"error":"tidak dikenal"}`, http.StatusForbidden)
			return
		}
		var items []map[string]any
		for _, id := range ids {
			items = append(items, objects[fmt.Sprint(id)])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	})

	mux.HandleFunc("/api/orders/", func(w http.ResponseWriter, r *http.Request) {
		u := s.who(r)
		id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
		obj, ok := objects[id]
		if !ok {
			http.Error(w, `{"error":"tidak ditemukan"}`, http.StatusNotFound)
			return
		}
		if s.guarded && obj["owner"] != u {
			// Perilaku benar: tolak yang bukan pemilik.
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(obj)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><html><body>root</body></html>")
	})
	return mux
}

func bolaTarget(t *testing.T, base string, guarded bool) Target {
	t.Helper()
	tg := Target{
		Name:   "uji",
		URL:    base,
		Authz:  true,
		Tokens: Tokens{"alice": "alice-token", "bob": "bob-token"},
	}
	return tg
}

func bolaEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/api/orders", Method: http.MethodGet},
	}
}

// TestOwnershipSubstitutionMenangkapKebocoran — server dengan ownership yang
// tidak diperiksa harus menghasilkan verdict bocor-terbukti, lengkap dengan
// ID objek yang benar-benar milik alice.
func TestOwnershipSubstitutionMenangkapKebocoran(t *testing.T) {
	srv := httptest.NewServer(bolaServer{guarded: false, owner: "alice"}.handler())
	defer srv.Close()

	tg := bolaTarget(t, srv.URL, false)
	rep := ProbeOwnership(context.Background(), tg.HTTPClient(), tg, bolaEndpoints(), "alice", "bob", 0)

	if rep.Proven == 0 {
		t.Fatalf("server tidak memeriksa kepemilikan; harusnya ada yang terbukti bocor,_guard=%d unknown=%d", rep.Guarded, rep.Unreadable)
	}
	for _, sw := range rep.Swaps {
		if sw.Verdict != OwnerLeak {
			continue
		}
		if sw.Owner != "alice" || sw.Intruder != "bob" {
			t.Errorf("salah pasangan akun: %s vs %s, mau alice vs bob", sw.Owner, sw.Intruder)
		}
		if sw.ObjectID == "2001" {
			t.Errorf("ID %s milik bob, seharusnya tidak diuji sebagai milik alice", sw.ObjectID)
		}
		if !strings.Contains(sw.Note, "kredensial orang lain") {
			t.Errorf("catatan bukti kurang tegas: %q", sw.Note)
		}
	}
}

// TestOwnershipSubstitutionTidakSalahLaporPadaServerTerjaga — server yang
// memeriksa kepemilikan dengan benar harus TIDAK menghasilkan satu pun
// temuan bocor. Ini pengaman terhadap false positive yang paling merusak.
func TestOwnershipSubstitutionTidakSalahLaporPadaServerTerjaga(t *testing.T) {
	srv := httptest.NewServer(bolaServer{guarded: true, owner: "alice"}.handler())
	defer srv.Close()

	tg := bolaTarget(t, srv.URL, true)
	rep := ProbeOwnership(context.Background(), tg.HTTPClient(), tg, bolaEndpoints(), "alice", "bob", 0)

	if rep.Proven != 0 {
		for _, sw := range rep.Swaps {
			if sw.Verdict == OwnerLeak {
				t.Errorf("server sudah terjaga tapi tetap dilaporkan bocor: %s — %s", sw.ObjectID, sw.Note)
			}
		}
	}
	if rep.Guarded == 0 {
		t.Errorf("server terjaga harus menghasilkan setidaknya satu 'terjaga', got guarded=%d unknown=%d", rep.Guarded, rep.Unreadable)
	}
}

// TestCollectIDsMenangkapNested — ID sering bersarang beberapa level dalam dan
// dinamai "OrderId", bukan "id". Kalau pengambil ID tidak menjangkau keduanya,
// seluruh metode ini diam-diam tidak menguji apa pun.
func TestCollectIDsMenangkapNested(t *testing.T) {
	body := []byte(`{"data":{"items":[{"OrderId":1001,"name":"a"},
	  {"order_id":1002,"name":"b"},{"id":1003}]},"total":3}`)
	got := collectIDs(body)
	want := map[string]bool{"1001": true, "1002": true, "1003": true}
	for _, g := range got {
		delete(want, g)
	}
	if len(want) != 0 {
		t.Errorf("ID yang terlewat: %v (ditemukan %v)", want, got)
	}
}

// TestCollectIDsMengabaikanAngkaBukanID — harga, timestamp, dan koordinat juga
// angka. Memakingsemua angka sebagai ID akan membuat tool menguji URL tak
// berguna dan Reported itu sebagai palsu.
func TestCollectIDsMengabaikanAngkaBukanID(t *testing.T) {
	body := []byte(`{"price":15000000,"year":2024,"lat":-6.2,"id":77}`)
	got := collectIDs(body)
	if len(got) != 1 || got[0] != "77" {
		t.Errorf("harus hanya menangkap id=77, dapat %v", got)
	}
}

// TestCollectIDsAbaikanNonJSON — halaman HTML bukan daftar objek.
func TestCollectIDsAbaikanNonJSON(t *testing.T) {
	if got := collectIDs([]byte(`<!doctype html><html>id="5"</html>`)); len(got) != 0 {
		t.Errorf("HTML tidak boleh menghasilkan ID, dapat %v", got)
	}
}

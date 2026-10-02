# lumen

Pemeta permukaan aplikasi web untuk review keamanan — dengan fokus pada SPA
di mana rute API **tidak ada di HTML**.

```
lumen -target https://app.example.com
```

## Masalah yang dipecahkan

Untuk aplikasi React/Next/Vue, HTML yang dikirim ke browser praktis kosong:
satu `<div id="root">` dan beberapa tag `<script>`. Semua rute API ada di
dalam JavaScript bundle sebagai string literal.

Akibatnya crawler biasa — dan humans yang sedang klik-klik — selalu melihat
"halaman login saja" dan berhenti di sana. Rute yang sebenarnya tidak pernah
tampak.

`lumen` membaca bundle-nya. Pada target pertama yang diuji, dari **1 halaman
HTML** ditemukan **76 endpoint**, termasuk 46 endpoint admin — nol di antaranya
pernah muncul di HTML.

## Yang dilakukan

| Tahap | Isi |
|---|---|
| Crawl | BFS dalam scope, rate-limited, kanonikalisasi URL |
| Bundle | Baca tiap `<script src>`, tarik path + method HTTP |
| Analisis | Header keamanan, cookie, CORS, tech stack, kredensial tertanam |
| Probe | `OPTIONS` ke endpoint hasil ekstraksi — **tidak ada** perubahan state |

## Prinsip yang dipegang

**Satu origin.** Guard di `internal/scope` memblokir host lain dan mencatat
penolakannya di laporan (`scope_denied`). Tanpa itu, satu `<script src>` ke CDN
saja sudah cukup menarik crawler keluar dari target. Penolakan dicatat supaya
bisa diaudit, bukan terjadi diam-diam.

**Tidak ada metode destruktif.** Hanya `GET` dan `OPTIONS`. Tidak ada `POST`,
`PUT`, `PATCH`, atau `DELETE` — jadi tidak ada perubahan state di server.
Menguji apakah endpoint butuh autentikasi memang penting; mengujinya dengan
menulis ke database bukan bagian dari pemetaan.

**Tidak menyimpulkan kerentanan.** Alat ini menunjuk hal yang menarik.
Penilaian tetap milik manusia. `AKSES-TANPA-AUTH` pada `OPTIONS` berarti
*coba*, bukan *bukti* — banyak server membalas 200 ke `OPTIONS` lalu 401 ke
`GET` sebenarnya.

**Tidak ada target hardcoded.** Nol referensi ke situs tertentu di seluruh
kode. Semua lewat flag. Tool ini untuk aplikasi siapa pun.

## Install

```bash
make            # fmt, vet, test, build
make race       # test dengan race detector
```

Binary: `bin/lumen`. Pure Go stdlib — tanpa dependency eksternal.

## Pakai

```bash
lumen -target https://app.example.com

# lebih konservatif (host produksi milik orang lain)
lumen -target https://app.example.com -delay 1s -conc 2

# tanpa probe — hanya pemetaan pasif
lumen -target https://app.example.com -probe=false

# simpan baseline lalu bandingkan setelah patch
lumen -target https://app.example.com -name before
lumen -target https://app.example.com -name after
diff <(jq -S .endpoints out/before.json) <(jq -S .endpoints out/after.json)
```

Output: `out/<nama>.json` (untuk agent/diff) dan `out/<nama>.txt` (untuk mata).
Keduanya mode `0600` — laporan bisa memuat path internal dan potongan
kredensial.

### Flag

| Flag | Default | Arti |
|---|---|---|
| `-target` | — | URL target (wajib) |
| `-out` | `out` | direktori output |
| `-name` | dari host | nama file tanpa ekstensi |
| `-conc` | 4 | request paralel |
| `-delay` | 250ms | jeda minimal antar request |
| `-probe` | true | verifikasi `OPTIONS` |
| `-timeout` | 3m | batas waktu total |
| `-quiet` | false | ringkas saja |

## Struktur

```
cmd/lumen/          CLI: flag, wiring, output
internal/scope/     guard host + rate limiter
internal/extract/   parser HTML & JS — inti nilai alat ini
internal/mapper/    orkestrasi crawl
internal/probe/     verifikasi OPTIONS
internal/report/    JSON + ringkasan terminal
internal/model/     tipe data bersama
```

## Detail teknis yang layak diketahui

**Batas statement, bukan jendela karakter.** Untuk menentukan metode HTTP,
jendelanya dibatasi ke statement terdekat (delimiter `;` dan newline).
Bundle minified menaruh banyak request dalam satu baris tanpa spasi:

```js
axios.post("/api/a",{});axios({method:"DELETE",url:"/api/b"})
```

Jendela karakter tetap akan melewati batas itu dan mengambil method milik
request sebelah — metode tertukar diam-diam. Kurung kurawal sengaja tidak
dipakai sebagai delimiter: object literal adalah bagian dari pemanggilan,
jadi `axios({method:"POST",url:"/api/x"})` akan terpotong tepat sebelum
method-nya terbaca.

**Pola pemanggilan, bukan nama pustaka.** Regex menangkap `nama.metode("path")`
dengan bentuk umum, bukan daftar `fetch|axios`. Aplikasi nyata hampir selalu
memakai instance sendiri (`const api = axios.create(); api.post(...)`) dan pola
hardcode akan melewatkan semuanya. Test pertama justru gagal karena
`api.post(...)` tidak dikenali.

**Kredensial disamarkan di laporan.** Nilai rahasia tidak pernah dicetak utuh
ke output — yang muncul adalah tipe (`stripe-key`, `github-token`) dan
sampel tersamar. Kalau label-nya diisi nilai yang cocok, laporan diam-diam
menyalin kredensial asli ke file dan ke terminal.

## Test

```
internal/extract/  test_test.go   rute dari bundle, metode, kredensial, kanonikalisasi
internal/scope/    test_scope.go  guard menolak host lain, termasuk prefix menipu
internal/mapper/   test_mapper.go end-to-end dengan SPA palsu
```

`make race` wajib jalan sebelum commit — mapper punya worker paralel dan pernah
memang punya data race (cookie menempel ke halaman yang salah karena ditulis
via `m.pages[len-1]`).

## Batasan yang diketahui

- Hanya satu origin. Alias/CDN yang memblokir crawl tidak dipetakan.
- Tidak membaca service worker atau IndexedDB.
- Regex mengurai JS, bukan parser AST. Path hasil interpolasi (template
  literal) masuk apa adanya: `/admin/users/${id}`.
- `probe` hanya `OPTIONS`; servis yang tidak menangani `OPTIONS` akan terlihat
  405 walau `GET`-nya sebenarnya terbuka.

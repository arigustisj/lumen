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

## Pakai di Termux (Android)

```bash
make termux                        # -> dist/lumen-termux (aarch64, statis)
scp dist/lumen-termux <user>@<ip>:~/bin/lumen

# di HP
termux-chmod 755 ~/bin/lumen
~/bin/lumen -target https://app.example.com -width 46
```

Termux menjalankan binary Linux native, jadi binary amd64 dari WSL tidak bisa
dipakai. `-width 46` itu untuk layar HP; tanpa itu baris akan terpotong tepat
di bagian yang paling penting. Warna dan unicode otomatis menyesuaikan —
`NO_COLOR=1` kalau mau polos.

## Struktur

Satu package di root, supaya bisa di-import oleh project lain:

```
go.mod            module github.com/0xlzy-sam/lumen
scope.go          guard host + rate limiter
extract.go        parser HTML & JS — inti nilai alat ini
mapper.go         orkestrasi crawl
probe.go          verifikasi OPTIONS
owasp.go          taksonomi OWASP + classifier + coverage
sarif.go          ekspor SARIF 2.1.0
report.go         JSON + tampilan terminal
tui.go            warna, box, wrap, deteksi lebar terminal
model.go          tipe data + identitas tool
cmd/lumen/        CLI tipis
```

Dipakai sebagai library:

```go
import "github.com/0xlzy-sam/lumen"

m := lumen.NewMapper(lumen.MapperConfig{Target: u, Conc: 4})
m.Run(ctx)
pages, eps, findings, _ := m.Snapshot()
cands := lumen.Classify(eps, findings)
cov := lumen.BuildCoverage(lumen.Report{Stats: stats})
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
extract_test.go   rute dari bundle, metode, kredensial, kanonikalisasi
scope_test.go     guard menolak host lain, termasuk prefix menipu
mapper_test.go    end-to-end dengan SPA palsu
owasp_test.go     klasifikasi BOLA/BFLA, kejujuran coverage, SARIF, exit code
```

`make race` wajib jalan sebelum commit — mapper punya worker paralel dan pernah
memang punya data race (cookie menempel ke halaman yang salah karena ditulis
via `m.pages[len-1]`).

## Deteksi: OWASP + SARIF

Hasil `lumen` bukan cuma daftar path. Endpoint di-klasifikasi ke
**OWASP API Security Top 10 (2023)** dan **OWASP Web Top 10 (2021)**, masing-masing
dengan ID CWE supaya bisa di-search dan diproses tool lain.

Klasifikasi berbasis sinyal statis — pola path, flag probe, header yang hilang.
Lumen tidak pernah melakukan login, jadi **hasilnya kandidat, bukan temuan
terbukti**. Setiap kandidat membawa:

- `signal` — bukti statis yang memunculkannya
- `verify` — langkah konkret untuk mengonfirmasi **atau menyangkal**
- `remediate` — arah perbaikan

Dua kelas yang paling fruitful di API modern, dan keduanya butuh dua akun
untuk dibuktikan — itu sebabnya lumen tidak bisa menyelesaikannya sendiri:

| Kategori | Kapan muncul |
|---|---|
| **API1:2023** BOLA | path dengan parameter objek, mis. `/api/orders/${id}` |
| **API5:2023** BFLA | path `/admin` atau `/internal`, apalagi yang 2xx tanpa auth |

Confidence naik hanya karena sinyal yang benar-benar diamati. Endpoint yang
hanya terlihat sebagai string di bundle **tidak pernah** dapat confidence
high — ada test yang menjaga itu (`TestClassifyTidakMengarangBukti`).

### SARIF 2.1.0

File `.sarif` bisa langsung masuk GitHub code scanning, GitLab, atau pipeline
mana pun yang baca SARIF. Kalau output pakai skema sendiri, setiap adopter
harus menulis parser dulu — dan pada praktiknya tidak ada yang mau.

Kandidat ditulis level **`note`**, bukan `error`. Menaikkannya bikin code
scanning beralam atas hal yang belum diperiksa, dan orang lalu mematikan
alarmnya seluruhnya — lebih buruk daripada tidak ada output.

### Exit code

```
0  tidak ada kandidat confidence tinggi
2  ada kandidat high
3  scan tidak bisa dipercaya — tidak ada bundle yang terbaca
```

Exit **3** itu sengaja. Tanpa itu, scan yang gagal membaca target terlihat
IDENTIK dengan scan yang bersih, dan itu penyebab paling umum pipeline hijau
palsu. Pakai `-exit-zero` untuk pemakaian manual.

### Coverage

Laporan selalu menyatakan apa yang **tidak** diuji. Tanpa itu, "tidak ada
temuan" hanya berarti "tidak ada yang kita lihat" — bukan "aman".

```
* dianalisis   header keamanan HTTP per halaman
* TIDAK diuji  logika otorisasi server — BOLA/BFLA butuh dua akun berbeda
* batas        hanya GET dan OPTIONS; tidak ada request yang mengubah state
```

Di Termux/HP menuju production orang lain, `-delay 1s -conc 2`.

## Batasan yang diketahui

- Hanya satu origin. Alias/CDN yang memblokir crawl tidak dipetakan.
- Tidak membaca service worker atau IndexedDB.
- Regex mengurai JS, bukan parser AST. Path hasil interpolasi (template
  literal) masuk apa adanya: `/admin/users/${id}`.
- `probe` hanya `OPTIONS`; servis yang tidak menangani `OPTIONS` akan terlihat
  405 walau `GET`-nya sebenarnya terbuka.

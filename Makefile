BIN     := bin/lumen
PKG     := ./cmd/lumen
LDFLAGS := -s -w

.PHONY: all build test race vet fmt clean run termux install help

all: fmt vet test build ## format, check, test, build

build: ## binary untuk mesin ini
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

test: ## jalankan test
	go test ./...

race: ## test dengan race detector — WAJIB sebelum commit
	go test -race ./...

vet: ## static check
	go vet ./...

fmt: ## format
	gofmt -l -w .

clean: ## hapus build & output
	rm -rf bin out

run: build ## scan target: make run TARGET=https://app.example.com
	@test -n "$(TARGET)" || (echo "pakai: make run TARGET=https://app.example.com"; exit 2)
	$(BIN) -target $(TARGET) $(ARGS)

# ── Termux (Android) ───────────────────────────────────────────────────────
# Termux menjalankan binary Linux native. Binary Linux/amd64 dari WSL tidak
# bisa dipakai — arsitekturnya beda, dan Android tidak punya pustaka sistem
# yang sama. aarch64 adalah hampir semua phone sekarang.
#
# CGO_ENABLED=0 wajib: binary harus benar-benar statis, tidak menarik pustaka
# dari device. Kalau tidak, errornya muncul di HP dengan pesan yang tidak
# daripada kerjakan sekarang.
# daripada kerjakan sekarang.
termux: ## binary untuk Termux di Android (aarch64, statis)
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -trimpath -ldflags "$(LDFLAGS)" -o dist/lumen-termux $(PKG)
	@echo "== binary =="; file dist/lumen-termux
	@echo "== dynamic deps (harus kosong) =="
	@readelf -d dist/lumen-termux 2>/dev/null | grep -i needed || echo "  statis, tanpa dynamic linking"
	@echo "== salin ke HP =="
	@echo "  scp dist/lumen-termux <user>@<ip>:~/bin/lumen"

install: build ## pasang ke ~/.local/bin
	@mkdir -p $(HOME)/.local/bin
	install -m 0755 $(BIN) $(HOME)/.local/bin/lumen
	@echo "terpasang: $(HOME)/.local/bin/lumen"

help: ## daftar target
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}'

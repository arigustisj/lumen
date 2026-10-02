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
# Termux menjalankan binary Linux native, jadi binary linux/amd64 dari WSL
# tidak bisa dipakai.
#
# TAPI GOOS=linux juga tidak bisa. Android sejak API 21 mewajibkan
# executable berbentuk PIE (ET_DYN); binary GOOS=linux dibangun sebagai
# static ET_EXEC dan ditolak linker Android dengan:
#
#     error: "..." has unexpected e_type: 2
#
# e_type 2 = ET_EXEC. Build dengan GOOS=android menghasilkan PIE dengan
# PT_INTERP /system/bin/linker64, yang memang linker milik Android — inilah
# yang dipakai Termux. Tidak ada entry NEEDED, jadi binary-nya self-contained
# dan tidak butuh pustaka dari device.
termux: ## binary untuk Termux di Android (arm64 PIE)
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
		go build -trimpath -ldflags "-s -w" -o dist/lumen-termux $(PKG)
	@echo "== binary =="; file dist/lumen-termux
	@echo "== e_type (harus DYN / PIE, BUKAN EXEC) =="
	@readelf -h dist/lumen-termux | grep -E 'Type|Machine'
	@readelf -h dist/lumen-termux | grep -q 'DYN' \
		|| { echo "  GAGAL: e_type bukan PIE, Android akan menolaknya"; exit 1; }
	@echo "  PIE — akan diterima Android"
	@echo "== interpreter =="
	@readelf -l dist/lumen-termux | grep -i 'interpreter' || true
	@echo "== dynamic libs (boleh kosong) =="
	@readelf -d dist/lumen-termux 2>/dev/null | grep -i needed || echo "  tidak ada NEEDED — self-contained"
	@echo "== salin ke HP =="
	@echo "  scp dist/lumen-termux <user>@<ip>:~/bin/lumen"

install: build ## pasang ke ~/.local/bin
	@mkdir -p $(HOME)/.local/bin
	install -m 0755 $(BIN) $(HOME)/.local/bin/lumen
	@echo "terpasang: $(HOME)/.local/bin/lumen"

help: ## daftar target
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-9s\033[0m %s\n", $$1, $$2}'

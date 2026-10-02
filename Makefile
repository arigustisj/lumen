BIN := bin/lumen
PKG := ./cmd/lumen

.PHONY: all build test race vet fmt clean run help

all: fmt vet test build ## format, check, test, build

build: ## build binary ke bin/lumen
	@mkdir -p bin
	go build -trimpath -o $(BIN) $(PKG)

test: ## jalankan test
	go test ./...

race: ## jalankan test dengan race detector (WAJIB: mapper punya worker paralel)
	go test -race ./...

vet: ## static check
	go vet ./...

fmt: ## format
	gofmt -l -w .

clean: ## hapus build & output
	rm -rf bin out

run: build ## scan target, ganti TARGET=...
	@test -n "$(TARGET)" || (echo "pakai: make run TARGET=https://app.example.com"; exit 2)
	$(BIN) -target $(TARGET) $(ARGS)

help: ## daftar target
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

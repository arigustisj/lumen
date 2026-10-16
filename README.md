# lumen

A command line tool that maps the attack surface of a web app for a security review. It is built for single page apps, where the API routes are not in the HTML but inside the JavaScript bundles.

## What it is

lumen crawls one site (one origin only), reads every JavaScript bundle it finds, and pulls out API paths, HTTP methods, security header problems, cookie and CORS issues, and secrets left in the code. It then sends `OPTIONS` requests to the endpoints it found. It only uses `GET` and `OPTIONS`, so it never changes data on the target.

Results are candidates for a human to check, not proven bugs. Each candidate is mapped to OWASP API Top 10 (2023) and OWASP Web Top 10 (2021) with a CWE id, a way to verify it, and a fix direction. Every report also states what was not tested.

Only scan systems you own or have permission to test.

## Requirements

- Go 1.25 or newer
- No other dependencies

## Install and run

```bash
make            # format, vet, test, build -> bin/lumen
make install    # copy the binary to ~/.local/bin/lumen
```

```bash
lumen -target https://app.example.com
lumen -target https://app.example.com -delay 1s -conc 2   # gentler
lumen -target https://app.example.com -probe=false        # passive only
lumen -target https://app.example.com -diff               # compare with the previous scan
lumen                                                     # no -target: opens the home screen with scan history
```

Common flags: `-target`, `-out` (output folder, default `out`), `-name`, `-conc`, `-delay`, `-timeout`, `-probe`, `-sarif`, `-markdown`, `-diff`, `-config` (YAML file for several targets), `-authz`, `-bola`, `-no-tui`, `-exit-zero`, `-version`. Run `lumen -h` for the full list.

Output goes to `out/`: a JSON report, a Markdown report for AI agents, and a SARIF 2.1.0 file for code scanning. These files can contain internal paths and pieces of secrets, so they are git-ignored.

Exit codes: `0` no high confidence candidate, `2` at least one high candidate, `3` the scan could not be trusted (no bundle could be read). Use `-exit-zero` for manual runs.

For authorization checks across several targets, copy `lumen.example.yaml` to `lumen.yaml` and fill it in. `lumen.yaml` is git-ignored because it holds tokens.

### Build for Termux (Android)

```bash
make termux     # writes dist/lumen-termux (arm64)
```

Copy the file to the phone, run `termux-chmod 755` on it, and use `-width 46` on small screens.

## Use as a library

The root package can be imported by other Go projects:

```go
import "github.com/arigustisj/lumen"

m := lumen.NewMapper(lumen.MapperConfig{Target: u, Conc: 4})
m.Run(ctx)
pages, eps, findings, _ := m.Snapshot()
cands := lumen.Classify(eps, findings)
```

## Environment variables

lumen needs no secrets or `.env` file. These optional variables only change the display:

- `NO_COLOR`: turn colors off.
- `LUMEN_COLOR`: set to `always` to force colors.
- `LUMEN_UNICODE`: set to `1` to force unicode characters.
- `COLUMNS`: terminal width.

## Run tests

```bash
make test       # go test ./...
make race       # with the race detector, run this before committing
```

## Deploy

This repo is not deployed. It is a tool: build it with `make`.

## Project layout

```
cmd/lumen/    command line entry point
scope.go      same-origin guard and rate limiter
extract.go    HTML and JavaScript parser (the core of the tool)
mapper.go     crawl orchestration
probe.go      OPTIONS verification
owasp.go      OWASP classification and coverage
bola.go, authz.go   two-account authorization checks
sarif.go, report.go, mdreport.go   report writers
tui*.go       terminal screens
Makefile      build, test, termux targets
```

## Known limits

- One origin only. CDNs and aliases are not mapped.
- It does not read service workers or IndexedDB.
- JavaScript is read with regular expressions, not a full parser.
- `OPTIONS` can answer 405 even when `GET` is open.

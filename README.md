# lumen

A command line tool that maps the attack surface of a web app for a security review. It is built for single page apps, where the API routes are not in the HTML but inside the JavaScript bundles.

## What it is

lumen crawls one site (one origin only), reads every JavaScript bundle it finds, and pulls out API paths, HTTP methods, security header problems, cookie and CORS issues, and secrets left in the code. It then sends `OPTIONS` requests to the endpoints it found. It only uses `GET` and `OPTIONS`, so it never changes data on the target.

Results are candidates for a human to check, not proven bugs. They are mapped to OWASP API Top 10 (2023) and OWASP Web Top 10 (2021), and every report states what was not tested.

This is an early copy of the tool. The newer version, with the home screen, history, diff and authorization checks, lives in a separate repository.

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
```

Flags: `-target`, `-out` (default `out`), `-name`, `-conc`, `-delay`, `-timeout`, `-probe`, `-sarif`, `-quiet`, `-no-color`, `-ascii`, `-width`, `-exit-zero`, `-version`. Run `lumen -h` for details.

Output goes to `out/` (JSON report and a SARIF 2.1.0 file). These files can contain internal paths and pieces of secrets, so they are git-ignored.

Exit codes: `0` no high confidence candidate, `2` at least one high candidate, `3` the scan could not be trusted. Use `-exit-zero` for manual runs.

For Termux on Android, run `make termux` and copy `dist/lumen-termux` to the phone.

## Environment variables

lumen needs no secrets or `.env` file. These optional variables only change the display: `NO_COLOR`, `LUMEN_COLOR` (`always`), `LUMEN_UNICODE` (`1`), `COLUMNS`.

## Run tests

```bash
make test
make race       # with the race detector
```

## Deploy

This repo is not deployed. It is a tool: build it with `make`.

## Project layout

```
cmd/lumen/    command line entry point
scope.go      same-origin guard and rate limiter
extract.go    HTML and JavaScript parser
mapper.go     crawl orchestration
probe.go      OPTIONS verification
owasp.go      OWASP classification
sarif.go, report.go   report writers
tui.go        colors and terminal output
```

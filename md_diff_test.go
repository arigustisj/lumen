package lumen

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestMarkdownDiffMenyatakanPerubahanDanPeringatannya(t *testing.T) {
	oldRep := repFor("https://a.example")
	newRep := repFor("https://a.example")
	newRep.Endpoints = append(newRep.Endpoints,
		Endpoint{Method: "GET", Path: "/api/admin", Origin: OriginJS})
	newRep.Findings = append(newRep.Findings, Finding{
		Title: "Endpoint admin terbuka", Kind: "route", Severity: SevHigh,
		Where: "https://a.example", Detail: "...",
	})
	d := DiffReports(oldRep, newRep)

	run := Run{Target: newRep.Target, At: time.Now(), File: "a/x.json"}
	path := t.TempDir() + "/r.md"
	if err := WriteMarkdownDiff(path, newRep, nil, newRep.Coverage, run, &d); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	md := string(b)

	for _, w := range []string{
		"## Perubahan sejak",
		"### Temuan baru (1)",
		"Endpoint admin terbuka",
		"### Endpoint baru (1)",
		"/api/admin",
	} {
		if !strings.Contains(md, w) {
			t.Errorf("markdown diff tidak memuat %q", w)
		}
	}
	// Bagian perubahan harus mendahului daftar temuan: agent yang_task-nya
	// "apa yang berubah" tidak perlu menggulir seluruh laporan.
	if strings.Index(md, "## Perubahan sejak") > strings.Index(md, "## Temuan") {
		t.Error("bagian perubahan harus ditulis sebelum daftar temuan")
	}
}

func TestMarkdownDiffMenperingatkanKalauCakupanTidakSebanding(t *testing.T) {
	oldRep := repFor("https://a.example")
	newRep := repFor("https://a.example")
	newRep.Pages = nil
	newRep.Endpoints = nil
	newRep.Findings = nil
	newRep.RootError = "dial tcp: lookup a.example: no such host"

	d := DiffReports(oldRep, newRep)
	path := t.TempDir() + "/r.md"
	if err := WriteMarkdownDiff(path, newRep, nil, newRep.Coverage, Run{}, &d); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	md := string(b)

	if !strings.Contains(md, "PERINGATAN KAKUPAN") {
		t.Error("peringatan cakupan wajib ada di markdown")
	}
	// "Endpoint hilang" tanpa peringatan akan dibaca sebagai perbaikan.
	if !strings.Contains(md, "Endpoint tidak terlihat") {
		t.Error("endpoint yang hilang karena scan tidak tuntas tidak boleh disebut hilang")
	}
	if strings.Contains(md, "### Endpoint hilang") {
		t.Error("label 'Endpoint hilang' tidak boleh dipakai saat cakupan tidak sebanding")
	}
}

func TestDiffTanpaBaselineTidakMenghapusSemuanya(t *testing.T) {
	rep := repFor("https://a.example")
	d := DiffReports(nil, rep)
	if len(d.RemovedEndpoints) != 0 {
		t.Errorf("tanpa baseline tidak boleh ada endpoint yang dianggap hilang: %v", d.RemovedEndpoints)
	}
	if d.CoverageComparable {
		t.Error("tanpa baseline, perbandingan tidak bisa dianggap sebanding")
	}
}

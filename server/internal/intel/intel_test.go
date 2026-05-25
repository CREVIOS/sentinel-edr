package intel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentinel/server/internal/model"
)

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	feed := `# test feed
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,hash,critical,unit
198.51.100.23,ip,high,unit-c2
c2.evil.test,domain,high,unit
plainhash0000000000000000000000000000000000000000000000000000bad
`
	if err := os.WriteFile(filepath.Join(dir, "f.ioc"), []byte(feed), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New()
	n, err := e.LoadDir(dir)
	if err != nil || n == 0 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	return e
}

func TestHashMatch(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{ID: "e1", Category: model.CatFile, File: &model.FileInfo{Hash: "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"}}
	d := e.Match(ev)
	if len(d) != 1 || d[0].Engine != "ioc" || d[0].Severity != model.SevCritical {
		t.Fatalf("hash match wrong: %+v", d)
	}
}

func TestIPAndDomainMatch(t *testing.T) {
	e := loadEngine(t)
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Remote: "198.51.100.23:443"}})) != 1 {
		t.Fatal("ip:port not matched")
	}
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Domain: "c2.evil.test"}})) != 1 {
		t.Fatal("domain not matched")
	}
	// subdomain of a listed parent
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Domain: "deep.c2.evil.test"}})) != 1 {
		t.Fatal("subdomain parent match failed")
	}
}

func TestNoFalsePositive(t *testing.T) {
	e := loadEngine(t)
	if d := e.Match(&model.Event{ID: "e", File: &model.FileInfo{Hash: "deadbeef"}, Network: &model.NetInfo{Remote: "8.8.8.8:53", Domain: "good.example.com"}}); len(d) != 0 {
		t.Fatalf("unexpected match: %+v", d)
	}
}

func TestURLFeedAndRefresh(t *testing.T) {
	// abuse.ch-style plain newline list with '#' comments and bare indicators.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# Feodo Tracker style\n203.0.113.99\nbad.feed.test\n"))
	}))
	defer srv.Close()

	// local dir feed merged with the remote feed.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.ioc"), []byte("198.51.100.7,ip,high,local\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := New()
	e.Sources(dir, []string{srv.URL})
	n, err := e.Refresh()
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 3 { // local ip + remote ip + remote domain
		t.Fatalf("want 3 indicators, got %d", n)
	}
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Remote: "203.0.113.99:80"}})) != 1 {
		t.Fatal("remote-feed ip not matched")
	}
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Domain: "bad.feed.test"}})) != 1 {
		t.Fatal("remote-feed domain not matched")
	}
	if len(e.Match(&model.Event{ID: "e", Network: &model.NetInfo{Remote: "198.51.100.7:22"}})) != 1 {
		t.Fatal("local-dir ip not matched after merge")
	}
}

func TestURLFeedErrorKeepsOtherSources(t *testing.T) {
	// A dead feed URL must not wipe indicators gathered from the working source.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "local.ioc"), []byte("c2.evil.test,domain,high,local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New()
	e.Sources(dir, []string{"http://127.0.0.1:1/nope"})
	n, err := e.Refresh()
	if err == nil {
		t.Fatal("expected error from dead feed")
	}
	if n != 1 {
		t.Fatalf("partial intel lost: want 1, got %d", n)
	}
}

func TestAutoDetectType(t *testing.T) {
	if classify("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") != KindHash {
		t.Fatal("hash not detected")
	}
	if classify("203.0.113.5") != KindIP || classify("2001:db8::1") != KindIP {
		t.Fatal("ip not detected")
	}
	if classify("evil.example.com") != KindDomain {
		t.Fatal("domain not detected")
	}
}

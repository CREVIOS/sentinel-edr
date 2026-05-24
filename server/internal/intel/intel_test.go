package intel

import (
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

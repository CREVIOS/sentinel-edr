package cases

import (
	"testing"
	"time"

	"github.com/sentinel/server/internal/model"
)

// fakeStore is a minimal in-memory CaseStore for the correlator tests.
type fakeStore struct {
	m map[string]*model.Case
}

func newFake() *fakeStore { return &fakeStore{m: map[string]*model.Case{}} }

func (f *fakeStore) InsertCase(c *model.Case) error {
	cp := *c
	f.m[c.ID] = &cp
	return nil
}
func (f *fakeStore) GetCase(id string) (*model.Case, error) {
	c, ok := f.m[id]
	if !ok {
		return nil, errNotFound
	}
	cp := *c
	return &cp, nil
}
func (f *fakeStore) ListCases(_ int, status string) ([]model.Case, error) {
	var out []model.Case
	for _, c := range f.m {
		if status == "" || string(c.Status) == status {
			out = append(out, *c)
		}
	}
	return out, nil
}

var errNotFound = &notFound{}

type notFound struct{}

func (*notFound) Error() string { return "not found" }

func mkDet(id, agent, host string, sev model.Severity, mitre ...string) *model.Detection {
	return &model.Detection{ID: id, AgentID: agent, Hostname: host, Severity: sev, MITRE: mitre, RuleName: "rule " + id}
}

func TestFoldsWithinWindow(t *testing.T) {
	c := New(newFake(), nil)
	c1, err := c.Add(mkDet("d1", "a1", "host1", model.SevLow, "T1059"))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := c.Add(mkDet("d2", "a1", "host1", model.SevCritical, "T1071"))
	if err != nil {
		t.Fatal(err)
	}
	if c1.ID != c2.ID {
		t.Fatal("second detection on same agent should fold into the same case")
	}
	if len(c2.DetectionIDs) != 2 {
		t.Fatalf("expected 2 linked detections, got %d", len(c2.DetectionIDs))
	}
	if c2.Severity != model.SevCritical {
		t.Fatalf("case severity should rise to critical, got %s", c2.Severity)
	}
	if len(c2.MITRE) != 2 {
		t.Fatalf("expected 2 unioned MITRE techniques, got %v", c2.MITRE)
	}
}

func TestSeparateCasePerAgent(t *testing.T) {
	c := New(newFake(), nil)
	c1, _ := c.Add(mkDet("d1", "a1", "host1", model.SevMedium))
	c2, _ := c.Add(mkDet("d2", "a2", "host2", model.SevMedium))
	if c1.ID == c2.ID {
		t.Fatal("different agents must get distinct cases")
	}
}

func TestNewCaseAfterWindow(t *testing.T) {
	c := New(newFake(), nil)
	first, _ := c.Add(mkDet("d1", "a1", "h", model.SevLow))
	// force the active reference to look stale
	c.mu.Lock()
	c.active["a1"] = ref{id: first.ID, last: time.Now().Add(-2 * window)}
	c.mu.Unlock()
	second, _ := c.Add(mkDet("d2", "a1", "h", model.SevLow))
	if first.ID == second.ID {
		t.Fatal("detection past the window should open a new case")
	}
}

func TestNoDuplicateDetectionID(t *testing.T) {
	c := New(newFake(), nil)
	c.Add(mkDet("d1", "a1", "h", model.SevLow))
	cs, _ := c.Add(mkDet("d1", "a1", "h", model.SevLow)) // same id (re-emit)
	if len(cs.DetectionIDs) != 1 {
		t.Fatalf("re-emitted detection should not duplicate, got %v", cs.DetectionIDs)
	}
}

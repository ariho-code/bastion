package scan

import "testing"

func TestGradeFromScore(t *testing.T) {
	cases := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {80, "B"}, {79, "C"},
		{70, "C"}, {69, "D"}, {55, "D"}, {54, "F"}, {0, "F"},
	}
	for _, c := range cases {
		if got := GradeFromScore(c.score); got != c.grade {
			t.Errorf("GradeFromScore(%d) = %q, want %q", c.score, got, c.grade)
		}
	}
}

func TestScoreByCategory(t *testing.T) {
	findings := []Finding{
		{Category: CategoryTransport, Status: StatusPass, Points: 10, MaxPoints: 10},
		{Category: CategoryTransport, Status: StatusFail, Points: 0, MaxPoints: 10},
		{Category: CategoryHeaders, Status: StatusPass, Points: 5, MaxPoints: 5},
		{Category: CategoryHeaders, Status: StatusInfo, Points: 0, MaxPoints: 0}, // excluded from scoring
	}
	cats, overall := scoreByCategory(findings)

	if len(cats) != 2 {
		t.Fatalf("expected 2 categories, got %d", len(cats))
	}
	// Transport: 10/20 = 50, Headers: 5/5 = 100. Overall: 15/25 = 60.
	if overall != 60 {
		t.Errorf("overall = %d, want 60", overall)
	}
	var transport CategoryScore
	for _, c := range cats {
		if c.Category == CategoryTransport {
			transport = c
		}
	}
	if transport.Score != 50 {
		t.Errorf("transport score = %d, want 50", transport.Score)
	}
	if transport.Pass != 1 || transport.Fail != 1 {
		t.Errorf("transport tally pass=%d fail=%d, want 1/1", transport.Pass, transport.Fail)
	}
}

func TestSortFindingsWorstFirst(t *testing.T) {
	findings := []Finding{
		{ID: "pass", Status: StatusPass, Severity: SeverityInfo},
		{ID: "crit", Status: StatusFail, Severity: SeverityCritical},
		{ID: "warn", Status: StatusWarn, Severity: SeverityMedium},
		{ID: "high", Status: StatusFail, Severity: SeverityHigh},
	}
	sortFindings(findings)
	want := []string{"crit", "high", "warn", "pass"}
	for i, id := range want {
		if findings[i].ID != id {
			t.Errorf("position %d = %q, want %q", i, findings[i].ID, id)
		}
	}
}

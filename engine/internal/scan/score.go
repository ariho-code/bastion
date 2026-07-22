package scan

import "sort"

// GradeFromScore maps a 0–100 score to a letter grade.
func GradeFromScore(pct int) string {
	switch {
	case pct >= 90:
		return "A"
	case pct >= 80:
		return "B"
	case pct >= 70:
		return "C"
	case pct >= 55:
		return "D"
	default:
		return "F"
	}
}

// categoryOrder controls the display order of categories in a report. Unknown
// categories are appended after these, alphabetically.
var categoryOrder = map[Category]int{
	CategoryTransport:  0,
	CategoryHeaders:    1,
	CategoryDNS:        2,
	CategoryCookies:    3,
	CategoryContent:    4,
	CategoryDisclosure: 5,
	CategorySurface:    6,
	CategoryIntel:      7,
}

// scoreByCategory aggregates findings into per-category scores and an overall
// score. Only findings with MaxPoints > 0 contribute to scoring; informational
// findings still count toward pass/warn/fail tallies.
func scoreByCategory(findings []Finding) ([]CategoryScore, int) {
	type acc struct {
		earned, max          int
		pass, warn, fail     int
		hasScored            bool
	}
	buckets := map[Category]*acc{}
	for _, f := range findings {
		a := buckets[f.Category]
		if a == nil {
			a = &acc{}
			buckets[f.Category] = a
		}
		if f.MaxPoints > 0 {
			a.earned += f.Points
			a.max += f.MaxPoints
			a.hasScored = true
		}
		switch f.Status {
		case StatusPass:
			a.pass++
		case StatusWarn:
			a.warn++
		case StatusFail:
			a.fail++
		}
	}

	cats := make([]CategoryScore, 0, len(buckets))
	var totalEarned, totalMax int
	for cat, a := range buckets {
		if !a.hasScored && a.pass == 0 && a.warn == 0 && a.fail == 0 {
			continue
		}
		label := CategoryLabels[cat]
		if label == "" {
			label = string(cat)
		}
		score := 0
		if a.max > 0 {
			score = int(float64(a.earned)/float64(a.max)*100 + 0.5)
		}
		cats = append(cats, CategoryScore{
			Category: cat, Label: label, Score: score,
			Earned: a.earned, Max: a.max,
			Pass: a.pass, Warn: a.warn, Fail: a.fail,
		})
		totalEarned += a.earned
		totalMax += a.max
	}

	sort.Slice(cats, func(i, j int) bool {
		oi, iok := categoryOrder[cats[i].Category]
		oj, jok := categoryOrder[cats[j].Category]
		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok // known categories first
		}
		return cats[i].Category < cats[j].Category
	})

	overall := 0
	if totalMax > 0 {
		overall = int(float64(totalEarned)/float64(totalMax)*100 + 0.5)
	}
	return cats, overall
}

var statusRank = map[Status]int{StatusFail: 0, StatusWarn: 1, StatusPass: 2, StatusInfo: 3}
var severityRank = map[Severity]int{
	SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3, SeverityInfo: 4,
}

// sortFindings orders findings worst-first: failures before warnings, then by
// severity, then by weight.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if statusRank[a.Status] != statusRank[b.Status] {
			return statusRank[a.Status] < statusRank[b.Status]
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		return a.MaxPoints > b.MaxPoints
	})
}

package schedule

import (
	"testing"
	"time"
)

func TestFiveFieldCronUsesHostLocalTime(t *testing.T) {
	previous := time.Local
	defer func() { time.Local = previous }()
	time.Local = time.FixedZone("test host", 2*60*60)

	cron, err := Parse("0 3 * * *")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, time.October, 31, 4, 0, 0, 0, time.Local)
	next, err := cron.Next(after)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.November, 1, 3, 0, 0, 0, time.Local)
	if !next.Equal(want) {
		t.Fatalf("next=%s, want %s", next, want)
	}
}

func TestSixFieldCronListsRangesAndSteps(t *testing.T) {
	cron, err := Parse("5,35 0-10/5 9-10 * * 1-5")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, time.November, 2, 9, 0, 4, 0, time.Local)
	next, err := cron.Next(after)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, time.November, 2, 9, 0, 5, 0, time.Local)
	if !next.Equal(want) {
		t.Fatalf("next=%s, want %s", next, want)
	}
}

func TestDayOfMonthAndWeekdayUseCronOrRule(t *testing.T) {
	cron, err := Parse("0 0 1 * 1")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Date(2026, time.November, 1, 0, 0, 0, 0, time.Local)
	next, err := cron.Next(after)
	if err != nil {
		t.Fatal(err)
	}
	if got := next.Weekday(); got != time.Monday || next.Day() != 2 {
		t.Fatalf("next=%s, want Monday Nov 2 (either day-of-month or weekday match)", next)
	}
}

func TestCronRejectsInvalidExpressions(t *testing.T) {
	for _, expression := range []string{"", "* * * *", "60 * * * *", "*/0 * * * *", "1-5-7 * * * *", "* * * * 8"} {
		if _, err := Parse(expression); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", expression)
		}
	}
}

package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type field struct {
	values []bool
	min    int
	max    int
	wild   bool
}

type Cron struct {
	second field
	minute field
	hour   field
	day    field
	month  field
	week   field
}

// Parse accepts numeric five-field cron or six-field cron with leading seconds.
func Parse(expression string) (Cron, error) {
	parts := strings.Fields(expression)
	if len(parts) != 5 && len(parts) != 6 {
		return Cron{}, fmt.Errorf("cron expression must have 5 fields or 6 fields with leading seconds")
	}
	var c Cron
	index := 0
	if len(parts) == 6 {
		seconds, errField := parseField(parts[0], 0, 59)
		if errField != nil {
			return Cron{}, fmt.Errorf("cron seconds: %w", errField)
		}
		c.second = seconds
		index = 1
	}
	var err error
	c.minute, err = parseField(parts[index], 0, 59)
	if err != nil {
		return Cron{}, fmt.Errorf("cron minutes: %w", err)
	}
	c.hour, err = parseField(parts[index+1], 0, 23)
	if err != nil {
		return Cron{}, fmt.Errorf("cron hours: %w", err)
	}
	c.day, err = parseField(parts[index+2], 1, 31)
	if err != nil {
		return Cron{}, fmt.Errorf("cron day of month: %w", err)
	}
	c.month, err = parseField(parts[index+3], 1, 12)
	if err != nil {
		return Cron{}, fmt.Errorf("cron month: %w", err)
	}
	c.week, err = parseField(parts[index+4], 0, 7)
	if err != nil {
		return Cron{}, fmt.Errorf("cron day of week: %w", err)
	}
	for value := range c.week.values {
		if value == 7 {
			c.week.values[0] = c.week.values[0] || c.week.values[7]
		}
	}
	if len(parts) == 5 {
		c.second, _ = parseField("0", 0, 59)
	}
	return c, nil
}

func parseField(expression string, min, max int) (field, error) {
	out := field{values: make([]bool, max+1), min: min, max: max, wild: expression == "*"}
	for _, item := range strings.Split(expression, ",") {
		if item == "" {
			return field{}, fmt.Errorf("empty list item")
		}
		base, stepText, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			parsed, err := strconv.Atoi(stepText)
			if err != nil || parsed < 1 {
				return field{}, fmt.Errorf("step must be a positive integer")
			}
			step = parsed
		}
		start, end := min, max
		if base != "*" {
			if first, second, found := strings.Cut(base, "-"); found {
				var err error
				start, err = strconv.Atoi(first)
				if err != nil {
					return field{}, fmt.Errorf("invalid range %q", base)
				}
				end, err = strconv.Atoi(second)
				if err != nil || start > end {
					return field{}, fmt.Errorf("invalid range %q", base)
				}
			} else {
				var err error
				start, err = strconv.Atoi(base)
				if err != nil {
					return field{}, fmt.Errorf("invalid value %q", base)
				}
				end = start
				if hasStep {
					end = max
				}
			}
		}
		if start < min || end > max {
			return field{}, fmt.Errorf("value must be from %d to %d", min, max)
		}
		for value := start; value <= end; value += step {
			out.values[value] = true
		}
	}
	count := 0
	for _, matched := range out.values {
		if matched {
			count++
		}
	}
	if count == 0 {
		return field{}, fmt.Errorf("field selects no values")
	}
	return out, nil
}

// Next returns the first matching time strictly after after, in host-local time.
func (c Cron) Next(after time.Time) (time.Time, error) {
	location := time.Local
	after = after.In(location)
	day := time.Date(after.Year(), after.Month(), after.Day(), 0, 0, 0, 0, location)
	limit := day.AddDate(8, 0, 0)
	hours, minutes, seconds := selected(c.hour), selected(c.minute), selected(c.second)
	for !day.After(limit) {
		if c.month.matches(int(day.Month())) && c.dayMatches(day) {
			for _, hour := range hours {
				for _, minute := range minutes {
					for _, second := range seconds {
						candidate := time.Date(day.Year(), day.Month(), day.Day(), hour, minute, second, 0, location)
						if candidate.After(after) && candidate.Year() == day.Year() && candidate.Month() == day.Month() && candidate.Day() == day.Day() && c.minute.matches(candidate.Minute()) && c.hour.matches(candidate.Hour()) && c.second.matches(candidate.Second()) {
							return candidate, nil
						}
					}
				}
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return time.Time{}, fmt.Errorf("cron expression has no occurrence within 8 years")
}

func (c Cron) dayMatches(value time.Time) bool {
	dayMatch := c.day.matches(value.Day())
	weekMatch := c.week.matches(int(value.Weekday()))
	if c.day.wild || c.week.wild {
		return dayMatch && weekMatch
	}
	return dayMatch || weekMatch
}

func (f field) matches(value int) bool {
	return value >= 0 && value < len(f.values) && f.values[value]
}

func selected(f field) []int {
	values := make([]int, 0, f.max-f.min+1)
	for value := f.min; value <= f.max; value++ {
		if f.matches(value) {
			values = append(values, value)
		}
	}
	return values
}

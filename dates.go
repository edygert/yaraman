package main

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/araddon/dateparse"
)

var (
	timezone   = "UTC"
	longMonths = map[string]string{
		"january":   "01",
		"february":  "02",
		"march":     "03",
		"april":     "04",
		"may":       "05",
		"june":      "06",
		"july":      "07",
		"august":    "08",
		"september": "09",
		"october":   "10",
		"november":  "11",
		"december":  "12",
	}

	mediumMonths = map[string]string{
		"sept": "09",
	}

	shortMonths = map[string]string{
		"jan": "01",
		"feb": "02",
		"mar": "03",
		"apr": "04",
		"may": "05",
		"jun": "06",
		"jul": "07",
		"aug": "08",
		"sep": "09",
		"oct": "10",
		"nov": "11",
		"dec": "12",
	}
)

func replaceMonth(fromDate string, months map[string]string) string {
	testDate := fromDate
	testDate = strings.ToLower(testDate)
	for monthName, monthNum := range months {
		index := strings.Index(testDate, monthName)
		if index == -1 {
			continue
		}
		if index == 0 {
			return strings.ReplaceAll(testDate, monthName, monthNum+"/")
		}
		if index > 4 {
			return testDate[:index] + "/" + monthNum + "/" + testDate[index+len(monthName):]
		}
		return monthNum + "/" + testDate[:index] + "/" + testDate[index+len(monthName):]
	}
	return fromDate
}

func normalizeDateInternal(fromDate string) string {
	if fromDate == "" {
		return fromDate
	}

	testDate := fromDate

	// Chop off the time
	if len(testDate) > 10 &&
		strings.Contains(testDate, "T") && strings.Contains(testDate, "Z") {
		testDate = testDate[:10]
	}
	if strings.Index(testDate, " ") > 0 && strings.Index(testDate, ":") > 0 {
		testDate = testDate[:strings.Index(testDate, " ")]
	}

	// Change spaces, .'s, and -'s to slashes
	if strings.Count(testDate, " ") == 2 {
		testDate = strings.ReplaceAll(testDate, " ", "/")
	}
	if strings.Count(testDate, ".") == 2 {
		testDate = strings.ReplaceAll(testDate, ".", "/")
	}
	//	if strings.Count(testDate, "-") == 2 {
	testDate = strings.ReplaceAll(testDate, "-", "/")
	testDate = strings.ReplaceAll(testDate, "_", "/")
	//	}

	// if date is 6 characters and numeric then return it yyyy/mm/dd format
	_, err := strconv.Atoi(testDate)
	if err == nil && len(testDate) == 6 {
		return testDate[4:] + "/" + testDate[:2] + "/" + testDate[2:4]
	}
	// Convert to lower case for month lookup
	testDate = strings.ToLower(testDate)
	testDate = replaceMonth(testDate, longMonths)
	testDate = replaceMonth(testDate, mediumMonths)
	testDate = replaceMonth(testDate, shortMonths)

	testDate = strings.ReplaceAll(testDate, " ", "")

	// Convert back to upper case for the "T" and "Z"
	testDate = strings.ToUpper(testDate)

	// Replace multiple slashes with one
	re := regexp.MustCompile(`[/][/]*`)
	testDate = string(re.ReplaceAll([]byte(testDate), []byte("/")))

	parts := strings.Split(testDate, "/")
	if len(parts) == 3 {
		// If all three parts are numeric, return the original
		// string with "-" changed to "/"
		n1, err1 := strconv.Atoi(parts[0])
		_, err2 := strconv.Atoi(parts[1])
		_, err3 := strconv.Atoi(parts[2])
		if err1 == nil && err2 == nil && err3 == nil {
			// Reverse the first two parts if n1 > 12 (put in MM/DD/YYYY format)
			if n1 > 12 && n1 < 32 {
				return parts[1] + "/" + parts[0] + "/" + parts[2]
			}
			return testDate
		}
	}
	if len(parts) == 2 {
		n1, err := strconv.Atoi(parts[0])
		if err == nil && n1 <= 12 {
			return parts[1] + "/" + parts[0]
		}
	}
	testDate = strings.ReplaceAll(testDate, ",/", "")
	return testDate
}

// Dates in YARA rules are in a deplorable state. Normalize as best we can for searching.
func normalizeDate(dateString string) string {
	normalizedDateString := normalizeDateInternal(dateString)
	if normalizedDateString == "" {
		return ""
	}
	normalizedDate, err := dateparse.ParseLocal(normalizedDateString)
	if err != nil {
		return ""
	}
	return normalizedDate.Format("2006-01-02")
}

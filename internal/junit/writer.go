package junit

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wleeb1010/soa-validate/internal/testrunner"
)

type Suites struct {
	XMLName  xml.Name `xml:"testsuites"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Errors   int      `xml:"errors,attr"`
	Skipped  int      `xml:"skipped,attr"`
	Time     string   `xml:"time,attr"`
	Suites   []Suite  `xml:"testsuite"`
}

type Suite struct {
	Name     string     `xml:"name,attr"`
	Tests    int        `xml:"tests,attr"`
	Failures int        `xml:"failures,attr"`
	Errors   int        `xml:"errors,attr"`
	Skipped  int        `xml:"skipped,attr"`
	Time     string     `xml:"time,attr"`
	Cases    []TestCase `xml:"testcase"`
}

type TestCase struct {
	Classname  string      `xml:"classname,attr"`
	Name       string      `xml:"name,attr"`
	Time       string      `xml:"time,attr"`
	Properties *Properties `xml:"properties,omitempty"`
	Skipped    *SkipTag    `xml:"skipped,omitempty"`
	Failure    *FailTag    `xml:"failure,omitempty"`
	Error      *FailTag    `xml:"error,omitempty"`
	SystemOut  string      `xml:"system-out,omitempty"`
}

type Properties struct {
	Props []Property `xml:"property"`
}

type Property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type SkipTag struct {
	Message string `xml:"message,attr"`
}

type FailTag struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr,omitempty"`
	Body    string `xml:",chardata"`
}

// Write serializes results as a single-suite JUnit XML doc. Each test case
// carries a <properties> block with one entry per evidence path ("vector",
// "live") so CI can differentiate passed-on-vector from passed-on-live from
// skipped-waiting-on-impl.
func Write(w io.Writer, suiteName string, results []testrunner.Result) error {
	total := len(results)
	var failures, errors, skipped int
	var totalDur time.Duration
	cases := make([]TestCase, 0, total)
	for _, r := range results {
		tc := TestCase{
			Classname: classify(r.ID),
			Name:      r.ID,
			Time:      fmtSeconds(r.Duration),
		}
		if len(r.Evidence) > 0 {
			var props []Property
			var outcomes []string
			for _, e := range r.Evidence {
				props = append(props, Property{
					Name:  "evidence." + string(e.Path),
					Value: string(e.Status),
				})
				props = append(props, Property{
					Name:  "evidence." + string(e.Path) + ".message",
					Value: e.Message,
				})
				outcomes = append(outcomes, fmt.Sprintf("%s=%s (%s)", e.Path, e.Status, e.Message))
			}
			tc.Properties = &Properties{Props: props}
			tc.SystemOut = strings.Join(outcomes, "\n")
		}
		switch r.Status {
		case testrunner.StatusSkip:
			skipped++
			tc.Skipped = &SkipTag{Message: r.Message}
		case testrunner.StatusFail:
			failures++
			tc.Failure = &FailTag{Message: r.Message, Body: r.Detail}
		case testrunner.StatusError:
			errors++
			tc.Error = &FailTag{Message: r.Message, Body: r.Detail}
		}
		totalDur += r.Duration
		cases = append(cases, tc)
	}

	suite := Suite{
		Name: suiteName, Tests: total, Failures: failures, Errors: errors,
		Skipped: skipped, Time: fmtSeconds(totalDur), Cases: cases,
	}
	doc := Suites{
		Name: suiteName, Tests: total, Failures: failures, Errors: errors,
		Skipped: skipped, Time: fmtSeconds(totalDur), Suites: []Suite{suite},
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return enc.Flush()
}

func classify(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) < 2 {
		return id
	}
	if len(parts) == 2 {
		return parts[0]
	}
	return parts[0] + "." + parts[1]
}

func fmtSeconds(d time.Duration) string {
	return fmt.Sprintf("%.6f", d.Seconds())
}

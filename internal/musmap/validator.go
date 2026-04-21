package musmap

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	svIDPattern = regexp.MustCompile(`^(HR|SV(-[A-Z0-9]+)+)-\d+$`)
	uvIDPattern = regexp.MustCompile(`^UV-[A-Z]+-\d+[a-z]?(†)?$`)
)

func ValidateSV(m *SVMustMap) error {
	if m == nil {
		return fmt.Errorf("nil SV must-map")
	}
	if len(m.Tests) == 0 {
		return fmt.Errorf("SV must-map has no tests")
	}
	var errs []string
	for id, t := range m.Tests {
		if !svIDPattern.MatchString(id) {
			errs = append(errs, fmt.Sprintf("test id %q does not match pattern (HR|SV-*)-NN", id))
		}
		if t.Name == "" {
			errs = append(errs, fmt.Sprintf("%s: empty name", id))
		}
		if t.Section == "" {
			errs = append(errs, fmt.Sprintf("%s: empty section", id))
		}
	}
	for _, phase := range m.ExecutionOrder.Phases {
		for _, id := range phase.Tests {
			if _, ok := m.Tests[id]; !ok {
				errs = append(errs, fmt.Sprintf("execution_order phase %d references unknown test %s", phase.Phase, id))
			}
		}
	}
	for anchor, cov := range m.MustCoverage {
		for _, id := range cov.Tests {
			if _, ok := m.Tests[id]; !ok {
				errs = append(errs, fmt.Sprintf("must_coverage %s references unknown test %s", anchor, id))
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("SV must-map invalid:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func ValidateUV(m *UVMustMap) error {
	if m == nil {
		return fmt.Errorf("nil UV must-map")
	}
	if len(m.Tests) == 0 {
		return fmt.Errorf("UV must-map has no tests")
	}
	var errs []string
	for id, t := range m.Tests {
		if !uvIDPattern.MatchString(id) {
			errs = append(errs, fmt.Sprintf("test id %q does not match pattern UV-*-NN[a][†]", id))
		}
		if t.Name == "" {
			errs = append(errs, fmt.Sprintf("%s: empty name", id))
		}
		if t.Assertion == "" {
			errs = append(errs, fmt.Sprintf("%s: empty assertion", id))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("UV must-map invalid:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

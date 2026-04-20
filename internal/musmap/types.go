package musmap

type SVMustMap struct {
	ID             string                       `json:"$id"`
	ArtifactVers   string                       `json:"artifact_version"`
	SpecVersion    string                       `json:"spec_version"`
	Generated      string                       `json:"generated"`
	Profiles       map[string]string            `json:"profiles"`
	SeverityScale  map[string]string            `json:"severity_scale"`
	TestCategories map[string]string            `json:"test_categories"`
	Tests          map[string]SVTest            `json:"tests"`
	TestsByCat     map[string][]string          `json:"tests_by_category"`
	MustCoverage   map[string]MustCoverageEntry `json:"must_coverage"`
	Uncovered      []string                     `json:"uncovered_musts_in_v1_0"`
	ExecutionOrder ExecutionOrder               `json:"execution_order"`
}

type SVTest struct {
	Name         string `json:"name"`
	Section      string `json:"section"`
	SectionTitle string `json:"section_title"`
	Profile      string `json:"profile"`
	Severity     string `json:"severity"`
	Summary      string `json:"summary"`
}

type MustCoverageEntry struct {
	Title string   `json:"title"`
	Tests []string `json:"tests"`
}

type ExecutionOrder struct {
	Notes  string  `json:"notes"`
	Phases []Phase `json:"phases"`
}

type Phase struct {
	Phase int      `json:"phase"`
	Name  string   `json:"name"`
	Tests []string `json:"tests"`
}

type UVMustMap struct {
	ID             string            `json:"$id"`
	ArtifactVers   string            `json:"artifact_version"`
	ProfileVers    string            `json:"profile_version"`
	BoundToCore    string            `json:"bound_to_core"`
	Generated      string            `json:"generated"`
	Profiles       map[string]string `json:"profiles"`
	TestCategories map[string]string `json:"test_categories"`
	ManualAddendum []string          `json:"manual_addendum_required_for"`
	ManualTests    []string          `json:"manual_addendum_tests"`
	Tests          map[string]UVTest `json:"tests"`
}

type UVTest struct {
	Name      string `json:"name"`
	Section   string `json:"section"`
	Profile   string `json:"profile"`
	Assertion string `json:"assertion"`
}

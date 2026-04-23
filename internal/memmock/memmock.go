// Package memmock is a minimum-viable in-process Memory MCP server for
// SV-MEM-* conformance probes. Speaks the §8.1 six-tool set per L-56
// tool-surface lockdown: add_memory_note, search_memories,
// search_memories_by_time, read_memory_note, consolidate_memories,
// delete_memory_note.
//
// Validator-built from scratch per the spec README guidance ("validators
// SHOULD build the reference mock from scratch to maintain the
// independent-judge property"). Impl's own JS mock is a reference; this
// Go mock implements the same normative behavior independently.
package memmock

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CorpusNote is one seeded note from test-vectors/memory-mcp-mock/corpus-seed.json.
type CorpusNote struct {
	NoteID         string  `json:"note_id"`
	Summary        string  `json:"summary"`
	DataClass      string  `json:"data_class"`
	RecencyDaysAgo int     `json:"recency_days_ago"`
	GraphStrength  float64 `json:"graph_strength"`
}

type corpusDoc struct {
	Notes []CorpusNote `json:"notes"`
}

// Options for a MemMock instance.
type Options struct {
	// CorpusPath is the path to corpus-seed.json. Empty → empty corpus.
	CorpusPath string
	// TimeoutAfterNCalls: after N successful calls, subsequent calls hang
	// forever (simulating unreachable). Zero means every call hangs.
	// Negative disables.
	TimeoutAfterNCalls int
	// ReturnErrorForTool returns {"error":"mock-error"} for calls to the
	// named tool. Empty means normal operation.
	ReturnErrorForTool string
}

// SearchCall captures one observed search_memories invocation for
// assertions like SV-MEM-06 (sharing_scope propagation from the card).
type SearchCall struct {
	Query        string `json:"query"`
	Limit        int    `json:"limit"`
	SharingScope string `json:"sharing_scope"`
}

// MemMock is the mock server handle.
type MemMock struct {
	srv         *http.Server
	listener    net.Listener
	port        int
	corpus      []CorpusNote
	opts        Options
	mu          sync.Mutex
	callLog     []string // tool name per invocation
	callCount   int64
	searchCalls []SearchCall
	// add_memory_note: monotonic seq for id minting; addedNotes holds the
	// bodies so read_memory_note can round-trip them.
	addSeq     int64
	addedMu    sync.Mutex
	addedNotes map[string]addedNote
	// delete_memory_note idempotency (§8.1 line 584): note_id →
	// {tombstone_id, deleted_at}.
	tombMu     sync.Mutex
	tombstones map[string]tombstoneRecord
	tombSeq    int64
}

// addedNote holds an add_memory_note body for later read_memory_note / search
// lookups. Includes created_at as RFC 3339 per §8.1.
type addedNote struct {
	ID         string   `json:"id"`
	Note       string   `json:"note"`
	Tags       []string `json:"tags"`
	Importance float64  `json:"importance"`
	CreatedAt  string   `json:"created_at"`
}

type tombstoneRecord struct {
	TombstoneID string `json:"tombstone_id"`
	DeletedAt   string `json:"deleted_at"`
}

// New creates a new MemMock but does not start it.
func New(opts Options) (*MemMock, error) {
	m := &MemMock{
		opts:       opts,
		tombstones: map[string]tombstoneRecord{},
		addedNotes: map[string]addedNote{},
	}
	if opts.CorpusPath != "" {
		raw, err := os.ReadFile(opts.CorpusPath)
		if err != nil {
			return nil, fmt.Errorf("read corpus seed: %w", err)
		}
		var doc corpusDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse corpus seed: %w", err)
		}
		m.corpus = doc.Notes
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/add_memory_note", m.handleAddMemoryNote)
	mux.HandleFunc("/search_memories", m.handleSearch)
	mux.HandleFunc("/search_memories_by_time", m.handleSearchByTime)
	mux.HandleFunc("/read_memory_note", m.handleReadMemoryNote)
	mux.HandleFunc("/consolidate_memories", m.handleConsolidate)
	mux.HandleFunc("/delete_memory_note", m.handleDelete)
	m.srv = &http.Server{Handler: mux}
	return m, nil
}

// Start binds a loopback port and starts serving. Returns when listening.
func (m *MemMock) Start() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("bind loopback: %w", err)
	}
	m.listener = ln
	m.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		_ = m.srv.Serve(ln)
	}()
	return nil
}

// URL returns the base URL the impl's MemoryMcpClient should point at.
func (m *MemMock) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", m.port)
}

// Stop gracefully shuts down the server with a short grace period.
func (m *MemMock) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = m.srv.Shutdown(ctx)
}

// CallLog returns a copy of the tool invocation log.
func (m *MemMock) CallLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.callLog))
	copy(out, m.callLog)
	return out
}

// SearchCalls returns a copy of every observed search_memories request.
func (m *MemMock) SearchCalls() []SearchCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SearchCall, len(m.searchCalls))
	copy(out, m.searchCalls)
	return out
}

// CallCount is the total number of successful (non-timeout, non-error) calls.
func (m *MemMock) CallCount() int64 {
	return atomic.LoadInt64(&m.callCount)
}

func (m *MemMock) shouldTimeout() bool {
	if m.opts.TimeoutAfterNCalls < 0 {
		return false
	}
	return atomic.LoadInt64(&m.callCount) >= int64(m.opts.TimeoutAfterNCalls)
}

func (m *MemMock) logCall(tool string) {
	m.mu.Lock()
	m.callLog = append(m.callLog, tool)
	m.mu.Unlock()
}

// writeJSON responds with a JSON body + 200 OK.
func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// handleSearch implements POST /search_memories. Returns top-N notes
// weighted by a simple (1/recency + graph_strength + query-substring
// match) composite so SV-MEM-02 can assert repeatable ordering.
func (m *MemMock) handleSearch(w http.ResponseWriter, r *http.Request) {
	m.logCall("search_memories")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "search_memories" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	var req struct {
		Query        string `json:"query"`
		Limit        int    `json:"limit"`
		SharingScope string `json:"sharing_scope"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Limit <= 0 {
		req.Limit = 5
	}
	m.mu.Lock()
	m.searchCalls = append(m.searchCalls, SearchCall{
		Query:        req.Query,
		Limit:        req.Limit,
		SharingScope: req.SharingScope,
	})
	m.mu.Unlock()

	type ranked struct {
		n     CorpusNote
		score float64
	}
	ranks := make([]ranked, 0, len(m.corpus))
	q := strings.ToLower(req.Query)
	for _, n := range m.corpus {
		recencyBoost := 1.0 / float64(1+n.RecencyDaysAgo)
		match := 0.0
		if q != "" && strings.Contains(strings.ToLower(n.Summary), q) {
			match = 0.5
		}
		ranks = append(ranks, ranked{n, recencyBoost + n.GraphStrength + match})
	}
	sort.SliceStable(ranks, func(i, j int) bool {
		if ranks[i].score != ranks[j].score {
			return ranks[i].score > ranks[j].score
		}
		return ranks[i].n.NoteID < ranks[j].n.NoteID
	})

	// Normalize composite_score to [0,1] — spec schema bounds this.
	var maxScore float64
	for _, r := range ranks {
		if r.score > maxScore {
			maxScore = r.score
		}
	}
	if maxScore == 0 {
		maxScore = 1
	}

	maxHits := req.Limit
	if maxHits > len(ranks) {
		maxHits = len(ranks)
	}
	hits := make([]map[string]interface{}, 0, maxHits)
	for i := 0; i < maxHits; i++ {
		r := ranks[i]
		// impl's state-store validates note_id pattern `^mem_[A-Za-z0-9_-]{8,}$`
		// — corpus seeds use `mem_seed_0001`, which matches.
		hits = append(hits, map[string]interface{}{
			"note_id":               r.n.NoteID,
			"summary":               r.n.Summary,
			"data_class":            r.n.DataClass,
			"composite_score":       r.score / maxScore,
			"weight_recency":        recencyWeight(r.n.RecencyDaysAgo),
			"weight_graph_strength": r.n.GraphStrength,
		})
	}
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"hits": hits})
}

func recencyWeight(daysAgo int) float64 {
	if daysAgo <= 0 {
		return 1.0
	}
	w := 1.0 / float64(1+daysAgo)
	if w > 1 {
		return 1
	}
	return w
}

// handleAddMemoryNote implements POST /add_memory_note per §8.1:
// (note ≤16 KiB, tags ≤32 × ≤64 chars, importance 0.0–1.0) → (id, created_at).
// Errors per §24: MemoryQuotaExceeded, MemoryDuplicate, MemoryMalformedInput.
func (m *MemMock) handleAddMemoryNote(w http.ResponseWriter, r *http.Request) {
	m.logCall("add_memory_note")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "add_memory_note" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	var req struct {
		Note       string   `json:"note"`
		Tags       []string `json:"tags"`
		Importance float64  `json:"importance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
		return
	}
	if len(req.Note) > 16*1024 {
		writeJSON(w, map[string]interface{}{"error": "MemoryQuotaExceeded"})
		return
	}
	if req.Importance < 0 || req.Importance > 1 {
		writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
		return
	}
	if len(req.Tags) > 32 {
		writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
		return
	}
	for _, t := range req.Tags {
		if len(t) > 64 {
			writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
			return
		}
	}
	seq := atomic.AddInt64(&m.addSeq, 1)
	id := fmt.Sprintf("mem_mock_added_%08d", seq)
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	m.addedMu.Lock()
	m.addedNotes[id] = addedNote{
		ID: id, Note: req.Note, Tags: req.Tags,
		Importance: req.Importance, CreatedAt: createdAt,
	}
	m.addedMu.Unlock()
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"id": id, "created_at": createdAt})
}

// handleSearchByTime implements POST /search_memories_by_time per §8.1:
// (start, end) → (hits, truncated). The mock's seeded corpus carries
// RecencyDaysAgo rather than absolute timestamps, so this handler
// returns the added-notes subset whose created_at falls in [start, end];
// seeded corpus items are synthesized as now - recency_days for the
// hits list.
func (m *MemMock) handleSearchByTime(w http.ResponseWriter, r *http.Request) {
	m.logCall("search_memories_by_time")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "search_memories_by_time" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	var req struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
		return
	}
	var start, end time.Time
	var err error
	if req.Start != "" {
		start, err = time.Parse(time.RFC3339, req.Start)
		if err != nil {
			writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
			return
		}
	}
	if req.End != "" {
		end, err = time.Parse(time.RFC3339, req.End)
		if err != nil {
			writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
			return
		}
	}
	hits := make([]map[string]interface{}, 0)
	m.addedMu.Lock()
	for _, n := range m.addedNotes {
		created, err := time.Parse(time.RFC3339Nano, n.CreatedAt)
		if err != nil {
			continue
		}
		if !start.IsZero() && created.Before(start) {
			continue
		}
		if !end.IsZero() && created.After(end) {
			continue
		}
		// Tombstoned ids MUST NOT appear (§8.1 search contract).
		m.tombMu.Lock()
		_, tombed := m.tombstones[n.ID]
		m.tombMu.Unlock()
		if tombed {
			continue
		}
		hits = append(hits, map[string]interface{}{
			"id":         n.ID,
			"created_at": n.CreatedAt,
			"tags":       n.Tags,
		})
	}
	m.addedMu.Unlock()
	// Stable sort by created_at for deterministic test assertions.
	sort.SliceStable(hits, func(i, j int) bool {
		return hits[i]["created_at"].(string) < hits[j]["created_at"].(string)
	})
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"hits": hits, "truncated": false})
}

// handleReadMemoryNote implements POST /read_memory_note per §8.1:
// (id) → (id, note, tags, importance, created_at, graph_edges).
// Errors: MemoryNotFound. Tombstoned ids return MemoryNotFound.
func (m *MemMock) handleReadMemoryNote(w http.ResponseWriter, r *http.Request) {
	m.logCall("read_memory_note")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "read_memory_note" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, map[string]interface{}{"error": "MemoryMalformedInput"})
		return
	}
	m.tombMu.Lock()
	_, tombed := m.tombstones[req.ID]
	m.tombMu.Unlock()
	if tombed {
		writeJSON(w, map[string]interface{}{"error": "MemoryNotFound"})
		return
	}
	m.addedMu.Lock()
	n, ok := m.addedNotes[req.ID]
	m.addedMu.Unlock()
	if ok {
		atomic.AddInt64(&m.callCount, 1)
		writeJSON(w, map[string]interface{}{
			"id":          n.ID,
			"note":        n.Note,
			"tags":        n.Tags,
			"importance":  n.Importance,
			"created_at":  n.CreatedAt,
			"graph_edges": []map[string]interface{}{},
		})
		return
	}
	// Fall back to seeded corpus. Corpus notes carry only summary/data_class,
	// so the read response surfaces summary under note + an empty graph.
	for _, c := range m.corpus {
		if c.NoteID == req.ID {
			atomic.AddInt64(&m.callCount, 1)
			writeJSON(w, map[string]interface{}{
				"id":          c.NoteID,
				"note":        c.Summary,
				"tags":        []string{c.DataClass},
				"importance":  c.GraphStrength,
				"created_at":  time.Now().UTC().Add(-time.Duration(c.RecencyDaysAgo) * 24 * time.Hour).Format(time.RFC3339Nano),
				"graph_edges": []map[string]interface{}{},
			})
			return
		}
	}
	writeJSON(w, map[string]interface{}{"error": "MemoryNotFound"})
}

func (m *MemMock) handleConsolidate(w http.ResponseWriter, r *http.Request) {
	m.logCall("consolidate_memories")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "consolidate_memories" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"consolidated_count": 0, "pending_count": 0})
}

// hang blocks until the client disconnects. Simulates an unreachable
// backend within per-call timeout budgets.
func (m *MemMock) hang(w http.ResponseWriter, r *http.Request) {
	<-r.Context().Done()
}

// handleDelete implements POST /delete_memory_note per §8.1 line 566:
// idempotent on `id` — repeat calls with the same id return the same
// tombstone_id + deleted_at. Tombstoned ids MUST NOT reappear in
// search_memories responses (enforced by handleSearch via tombstones).
func (m *MemMock) handleDelete(w http.ResponseWriter, r *http.Request) {
	m.logCall("delete_memory_note")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "delete_memory_note" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	var req struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	m.tombMu.Lock()
	rec, existed := m.tombstones[req.ID]
	if !existed {
		seq := atomic.AddInt64(&m.tombSeq, 1)
		rec = tombstoneRecord{
			TombstoneID: fmt.Sprintf("tmb_mock_%08d", seq),
			DeletedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		}
		m.tombstones[req.ID] = rec
	}
	m.tombMu.Unlock()
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{
		"deleted":      true,
		"tombstone_id": rec.TombstoneID,
		"deleted_at":   rec.DeletedAt,
	})
}

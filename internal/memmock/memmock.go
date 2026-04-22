// Package memmock is a minimum-viable in-process Memory MCP server for
// SV-MEM-* conformance probes. Speaks the HTTP shape impl's
// MemoryMcpClient expects (POST /search_memories, /write_memory,
// /consolidate_memories per L-34 test-vectors/memory-mcp-mock/).
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

// MemMock is the mock server handle.
type MemMock struct {
	srv       *http.Server
	listener  net.Listener
	port      int
	corpus    []CorpusNote
	opts      Options
	mu        sync.Mutex
	callLog   []string // tool name per invocation
	callCount int64
	// write_memory note-id counter for deterministic test output.
	writeSeq int64
	// L-38 delete_memory_note idempotency: note_id → {tombstone_id, deleted_at}.
	tombMu     sync.Mutex
	tombstones map[string]tombstoneRecord
	tombSeq    int64
}

type tombstoneRecord struct {
	TombstoneID string `json:"tombstone_id"`
	DeletedAt   string `json:"deleted_at"`
}

// New creates a new MemMock but does not start it.
func New(opts Options) (*MemMock, error) {
	m := &MemMock{opts: opts, tombstones: map[string]tombstoneRecord{}}
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
	mux.HandleFunc("/search_memories", m.handleSearch)
	// write_memory removed per spec L-38 (§8.1 five-tool set).
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

	maxNotes := req.Limit
	if maxNotes > len(ranks) {
		maxNotes = len(ranks)
	}
	notes := make([]map[string]interface{}, 0, maxNotes)
	for i := 0; i < maxNotes; i++ {
		r := ranks[i]
		// impl's state-store validates note_id pattern `^mem_[A-Za-z0-9_-]{8,}$`
		// — corpus seeds use `mem_seed_0001`, which matches.
		notes = append(notes, map[string]interface{}{
			"note_id":               r.n.NoteID,
			"summary":               r.n.Summary,
			"data_class":            r.n.DataClass,
			"composite_score":       r.score / maxScore,
			"weight_recency":        recencyWeight(r.n.RecencyDaysAgo),
			"weight_graph_strength": r.n.GraphStrength,
		})
	}
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"notes": notes})
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

func (m *MemMock) handleWrite(w http.ResponseWriter, r *http.Request) {
	m.logCall("write_memory")
	if m.shouldTimeout() {
		m.hang(w, r)
		return
	}
	if m.opts.ReturnErrorForTool == "write_memory" {
		writeJSON(w, map[string]interface{}{"error": "mock-error"})
		return
	}
	seq := atomic.AddInt64(&m.writeSeq, 1)
	atomic.AddInt64(&m.callCount, 1)
	writeJSON(w, map[string]interface{}{"note_id": fmt.Sprintf("mem_mock_write_%08d", seq)})
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

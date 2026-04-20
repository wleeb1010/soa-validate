package runner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Config struct {
	BaseURL     string
	BearerToken string
	TLSConfig   *tls.Config
	Timeout     time.Duration
}

type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	tr := &http.Transport{TLSClientConfig: cfg.TLSConfig}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout, Transport: tr},
	}
}

func (c *Client) BaseURL() string { return c.cfg.BaseURL }

func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.BearerToken)
	}
	return c.http.Do(req)
}

func (c *Client) Health(ctx context.Context) error { return c.probe(ctx, "/health") }
func (c *Client) Ready(ctx context.Context) error  { return c.probe(ctx, "/ready") }

func (c *Client) probe(ctx context.Context, path string) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return fmt.Errorf("probe %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("probe %s: %s", path, resp.Status)
	}
	return nil
}

type StreamEvent struct {
	EventID   string          `json:"event_id"`
	Sequence  int             `json:"sequence"`
	SessionID string          `json:"session_id"`
	TurnID    string          `json:"turn_id,omitempty"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp string          `json:"timestamp"`
}

// Stream opens SSE on /stream/v1/{sessionID} and invokes handle for each event
// until ctx is canceled or the server closes the stream. Non-SSE responses
// (4xx/5xx, wrong content-type) return an error immediately.
func (c *Client) Stream(ctx context.Context, sessionID string, handle func(StreamEvent) error) error {
	resp, err := c.Do(ctx, http.MethodGet, "/stream/v1/"+sessionID, nil)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stream status %s", resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		return fmt.Errorf("stream content-type %q; want text/event-stream", ct)
	}

	r := bufio.NewReader(resp.Body)
	var dataBuf strings.Builder
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := r.ReadString('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read sse: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if dataBuf.Len() > 0 {
				var ev StreamEvent
				if err := json.Unmarshal([]byte(dataBuf.String()), &ev); err != nil {
					return fmt.Errorf("parse sse event: %w", err)
				}
				if err := handle(ev); err != nil {
					return err
				}
				dataBuf.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataBuf.WriteString(strings.TrimPrefix(line, "data:"))
			dataBuf.WriteString("\n")
		}
	}
}

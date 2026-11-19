package gateway

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ScannerCapture writes every exchange of Snare's own scanner (identified by
// the scanner header or an excluded source address) to a JSON Lines file,
// unredacted and with exact timing. It exists to record ARTEX runs against
// the lab as test data for the detector, compiler and gate. It is off unless
// scanner.capture_file is set, and it never sees any other client's traffic.
//
// Like the recorder it never slows a request: exchanges go to a bounded
// queue, and a full queue or a full file drops and counts them.
type ScannerCapture struct {
	ch        chan CapturedExchange
	bodyLimit int
	maxBytes  int64
	log       *slog.Logger

	f       *os.File
	w       *bufio.Writer
	written int64

	captured, dropped atomic.Int64
	done              chan struct{}
	closeOnce         sync.Once
}

// CapturedExchange is one line of the capture file.
type CapturedExchange struct {
	Time       time.Time   `json:"time"`        // when the request arrived
	DurationMS float64     `json:"duration_ms"` // until the response finished
	Source     string      `json:"source"`      // client address as the gateway saw it
	Identified string      `json:"identified"`  // "header" or "source"
	Route      string      `json:"route"`
	Method     string      `json:"method"`
	Host       string      `json:"host"`
	Path       string      `json:"path"`
	RawQuery   string      `json:"query,omitempty"`
	ReqHeader  http.Header `json:"req_headers"` // the scanner header is already removed
	ReqBody    string      `json:"req_body,omitempty"`
	ReqBodyB64 string      `json:"req_body_b64,omitempty"` // instead of req_body when not UTF-8
	ReqBytes   int64       `json:"req_body_bytes"`
	Status     int         `json:"status"` // 0: no response (aborted)
	RespHeader http.Header `json:"resp_headers,omitempty"`
	RespBody   string      `json:"resp_body,omitempty"`
	RespB64    string      `json:"resp_body_b64,omitempty"`
	RespBytes  int64       `json:"resp_body_bytes"`
	Rejected   string      `json:"rejected,omitempty"` // "body_too_large" when the gateway refused it
}

// CaptureOptions configures OpenScannerCapture.
type CaptureOptions struct {
	Path      string
	BodyLimit int   // bytes kept of each body; default 1 MiB
	MaxBytes  int64 // file size cap; default 2 GiB
	Queue     int   // default 8192
	Log       *slog.Logger
}

// OpenScannerCapture opens (appends to) the capture file, mode 0600, and
// starts its writer.
func OpenScannerCapture(opt CaptureOptions) (*ScannerCapture, error) {
	if opt.BodyLimit <= 0 {
		opt.BodyLimit = 1 << 20
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 2 << 30
	}
	if opt.Queue <= 0 {
		opt.Queue = 8192
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.DiscardHandler)
	}
	f, err := os.OpenFile(opt.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("scanner capture: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("scanner capture: %w", err)
	}
	c := &ScannerCapture{
		ch: make(chan CapturedExchange, opt.Queue), bodyLimit: opt.BodyLimit, maxBytes: opt.MaxBytes,
		log: opt.Log, f: f, w: bufio.NewWriterSize(f, 256<<10), written: st.Size(), done: make(chan struct{}),
	}
	go c.run()
	return c, nil
}

// BodyLimit is how much of each body the capture keeps.
func (c *ScannerCapture) BodyLimit() int { return c.bodyLimit }

// Stats returns exchanges written and dropped since start.
func (c *ScannerCapture) Stats() (captured, dropped int64) {
	if c == nil {
		return 0, 0
	}
	return c.captured.Load(), c.dropped.Load()
}

// Submit queues one exchange without blocking.
func (c *ScannerCapture) Submit(ex CapturedExchange) {
	select {
	case c.ch <- ex:
	default:
		c.dropped.Add(1)
	}
}

func (c *ScannerCapture) run() {
	defer close(c.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case ex, ok := <-c.ch:
			if !ok {
				c.flush()
				return
			}
			c.write(ex)
		case <-tick.C:
			c.flush()
		}
	}
}

func (c *ScannerCapture) write(ex CapturedExchange) {
	line, err := json.Marshal(ex)
	if err != nil {
		c.dropped.Add(1)
		return
	}
	line = append(line, '\n')
	if c.written+int64(len(line)) > c.maxBytes {
		if c.dropped.Add(1) == 1 {
			c.log.Warn("scanner capture file is full; dropping", "max_bytes", c.maxBytes)
		}
		return
	}
	if _, err := c.w.Write(line); err != nil {
		c.dropped.Add(1)
		return
	}
	c.written += int64(len(line))
	c.captured.Add(1)
}

func (c *ScannerCapture) flush() {
	if err := c.w.Flush(); err != nil {
		c.log.Warn("scanner capture flush failed", "err", err)
	}
}

// Close drains the queue, flushes and closes the file. Submit must not be
// called after Close.
func (c *ScannerCapture) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.ch)
		<-c.done
		err = c.f.Close()
	})
	return err
}

// setBody fills the text or base64 field for a captured body.
func setBody(b []byte, text, b64 *string) {
	if len(b) == 0 {
		return
	}
	if utf8.Valid(b) {
		*text = string(b)
		return
	}
	*b64 = base64.StdEncoding.EncodeToString(b)
}

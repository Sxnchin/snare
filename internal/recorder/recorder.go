// Package recorder stores the benign corpus: request and response pairs the
// gateway sees on routes in record mode, plus imported HAR files. Every
// exchange is redacted before it is stored and sealed with AES-256-GCM.
package recorder

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snare-dev/snare/internal/store"
)

// Sources of an exchange.
const (
	SourceLive = "live"
	SourceHAR  = "har"
)

// Exchange is one captured request and response, before redaction.
type Exchange struct {
	Route    string
	Source   string
	Time     time.Time
	Duration time.Duration

	Method   string
	Host     string
	Path     string
	RawQuery string

	ReqHeader    http.Header
	ReqBody      []byte // at most the recorder's body cap
	ReqBodyBytes int64  // full length when known, else len(ReqBody)

	Status        int
	RespHeader    http.Header
	RespBody      []byte // as received: possibly compressed
	RespBodyBytes int64
}

// Record is the redacted exchange as stored (sealed) in the corpus.
type Record struct {
	Method         string      `json:"method"`
	Host           string      `json:"host"`
	Path           string      `json:"path"`
	Query          string      `json:"query,omitempty"`
	ReqHeaders     http.Header `json:"req_headers"`
	ReqBody        string      `json:"req_body,omitempty"`
	ReqBodyBytes   int64       `json:"req_body_bytes"`
	ReqTruncated   bool        `json:"req_truncated,omitempty"`
	Status         int         `json:"status"`
	RespHeaders    http.Header `json:"resp_headers"`
	RespBody       string      `json:"resp_body,omitempty"`
	RespBodyBytes  int64       `json:"resp_body_bytes"`
	RespTruncated  bool        `json:"resp_truncated,omitempty"`
	DurationMillis float64     `json:"duration_ms"`
}

// Options configures a Recorder.
type Options struct {
	LearningPeriod time.Duration
	MaxBodyBytes   int
	QueueSize      int
	Log            *slog.Logger
	Now            func() time.Time
}

// Recorder redacts, seals and stores exchanges.
type Recorder struct {
	st     *store.Store
	sealer *Sealer
	red    *Redactor
	opt    Options

	queue   chan Exchange
	dropped atomic.Int64
	stored  atomic.Int64
	wg      sync.WaitGroup

	mu      sync.Mutex
	started map[string]time.Time // route -> learning start
}

// New returns a recorder. Call Run to start the background writer.
func New(st *store.Store, sealer *Sealer, red *Redactor, opt Options) *Recorder {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.QueueSize <= 0 {
		opt.QueueSize = 1024
	}
	return &Recorder{
		st: st, sealer: sealer, red: red, opt: opt,
		queue:   make(chan Exchange, opt.QueueSize),
		started: map[string]time.Time{},
	}
}

// MaxBodyBytes is the per-side body cap the gateway should capture.
func (r *Recorder) MaxBodyBytes() int { return r.opt.MaxBodyBytes }

// Submit queues a live exchange without blocking. It returns false and
// counts a drop when the queue is full: recording never slows traffic.
func (r *Recorder) Submit(ex Exchange) bool {
	select {
	case r.queue <- ex:
		return true
	default:
		r.dropped.Add(1)
		return false
	}
}

// Stats returns stored and dropped counts since start.
func (r *Recorder) Stats() (stored, dropped int64) { return r.stored.Load(), r.dropped.Load() }

// Run writes queued exchanges until ctx is cancelled, then drains the queue.
func (r *Recorder) Run(ctx context.Context) {
	r.wg.Add(1)
	defer r.wg.Done()
	for {
		select {
		case ex := <-r.queue:
			r.writeBatch(ex)
		case <-ctx.Done():
			for {
				select {
				case ex := <-r.queue:
					r.writeBatch(ex)
				default:
					return
				}
			}
		}
	}
}

// Wait blocks until Run has returned.
func (r *Recorder) Wait() { r.wg.Wait() }

// writeBatch stores first and whatever else is already queued, up to 100
// exchanges, in one transaction.
func (r *Recorder) writeBatch(first Exchange) {
	batch := []Exchange{first}
	for len(batch) < 100 {
		select {
		case ex := <-r.queue:
			batch = append(batch, ex)
			continue
		default:
		}
		break
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := r.st.DB.BeginTx(ctx, nil)
	if err != nil {
		r.opt.Log.Error("corpus write", "err", err)
		r.dropped.Add(int64(len(batch)))
		return
	}
	n := 0
	for _, ex := range batch {
		if err := r.insert(ctx, tx, ex); err != nil {
			r.opt.Log.Warn("corpus exchange skipped", "route", ex.Route, "err", err)
			r.dropped.Add(1)
			continue
		}
		n++
	}
	if err := tx.Commit(); err != nil {
		r.opt.Log.Error("corpus commit", "err", err)
		r.dropped.Add(int64(n))
		return
	}
	r.stored.Add(int64(n))
}

// Store redacts, seals and stores one exchange synchronously (imports).
func (r *Recorder) Store(ctx context.Context, ex Exchange) error {
	tx, err := r.st.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := r.insert(ctx, tx, ex); err != nil {
		tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.stored.Add(1)
	return nil
}

func (r *Recorder) insert(ctx context.Context, tx *sql.Tx, ex Exchange) error {
	rec, params := r.Redact(ex)
	plain, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	sealed, err := r.sealer.Seal(plain, aadCorpus(ex.Route))
	if err != nil {
		return err
	}
	pj, _ := json.Marshal(params)
	ts := ex.Time
	if ts.IsZero() {
		ts = r.opt.Now()
	}
	if ex.Source == "" {
		ex.Source = SourceLive
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO corpus_exchanges
		(ts, route, source, method, path_template, status, duration_ms, req_bytes, resp_bytes, params, sealed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts.UTC().Format(time.RFC3339Nano), ex.Route, ex.Source, rec.Method, PathTemplate(rec.Path),
		rec.Status, rec.DurationMillis, rec.ReqBodyBytes, rec.RespBodyBytes, string(pj), sealed); err != nil {
		return err
	}
	if ex.Source == SourceLive {
		_, err = tx.ExecContext(ctx, `INSERT INTO route_learning(route, started_at) VALUES (?, ?)
			ON CONFLICT(route) DO NOTHING`, ex.Route, ts.UTC().Format(time.RFC3339Nano))
	}
	return err
}

func aadCorpus(route string) string { return "snare:corpus:v1:" + route }

// Redact turns a captured exchange into the record that will be stored, and
// lists the parameter names seen. Nothing unredacted leaves this function.
func (r *Recorder) Redact(ex Exchange) (Record, []string) {
	var params []string
	q, qnames := r.red.Query(ex.RawQuery)
	for _, n := range qnames {
		params = append(params, "query:"+n)
	}
	reqCT := ex.ReqHeader.Get("Content-Type")
	reqBody, bnames := r.red.Body(reqCT, ex.ReqBody)
	prefix := "json:"
	if strings.HasPrefix(strings.ToLower(reqCT), "application/x-www-form-urlencoded") {
		prefix = "form:"
	}
	for _, n := range bnames {
		params = append(params, prefix+n)
	}
	respBody := ""
	if raw, ok := decodeBody(ex.RespHeader.Get("Content-Encoding"), ex.RespBody); ok {
		respBody, _ = r.red.Body(ex.RespHeader.Get("Content-Type"), raw)
	} else {
		respBody = placeholder(KindBinary)
	}
	reqBytes := ex.ReqBodyBytes
	if reqBytes < int64(len(ex.ReqBody)) {
		reqBytes = int64(len(ex.ReqBody))
	}
	respBytes := ex.RespBodyBytes
	if respBytes < int64(len(ex.RespBody)) {
		respBytes = int64(len(ex.RespBody))
	}
	sort.Strings(params)
	return Record{
		Method:         strings.ToUpper(ex.Method),
		Host:           r.red.Text(ex.Host),
		Path:           r.red.Path(ex.Path),
		Query:          q,
		ReqHeaders:     r.red.Headers(ex.ReqHeader),
		ReqBody:        reqBody,
		ReqBodyBytes:   reqBytes,
		ReqTruncated:   reqBytes > int64(len(ex.ReqBody)),
		Status:         ex.Status,
		RespHeaders:    r.red.Headers(ex.RespHeader),
		RespBody:       respBody,
		RespBodyBytes:  respBytes,
		RespTruncated:  respBytes > int64(len(ex.RespBody)),
		DurationMillis: float64(ex.Duration.Microseconds()) / 1000,
	}, params
}

// decodeBody undoes gzip or deflate so the redactor sees text. A truncated
// stream yields what could be decoded. Other encodings (br, zstd) are not
// decoded; ok is false and the caller stores a placeholder, never the raw
// bytes, since compressed data could hide secrets from the redactor.
func decodeBody(encoding string, b []byte) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" || enc == "identity" || len(b) == 0 {
		return b, true
	}
	var rd io.Reader
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false
		}
		rd = zr
	case "deflate":
		rd = flate.NewReader(bytes.NewReader(b))
	default:
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(rd, 16<<20))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && len(out) == 0 {
		return nil, false
	}
	return out, true
}

var (
	reNumSeg  = regexp.MustCompile(`^\d+$`)
	reIDSeg   = regexp.MustCompile(`^([0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)
	reRedSeg  = regexp.MustCompile(`^\[REDACTED:[a-z]+\]$`)
	reLongSeg = regexp.MustCompile(`^[A-Za-z0-9_-]{40,}$`)
	// Dash-separated hex such as Juice Shop order ids (2641-64d2ab16ce8b49ee).
	reHexDash = regexp.MustCompile(`^[0-9a-fA-F-]{12,}$`)
)

// PathTemplate replaces identifier-like path segments so coverage groups
// /api/Products/1 and /api/Products/2 together.
func PathTemplate(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case reNumSeg.MatchString(s):
			segs[i] = "{n}"
		case reIDSeg.MatchString(s), reLongSeg.MatchString(s),
			reHexDash.MatchString(s) && strings.ContainsAny(s, "0123456789"):
			segs[i] = "{id}"
		case reRedSeg.MatchString(s):
			segs[i] = "{redacted}"
		}
	}
	return strings.Join(segs, "/")
}

// Learning reports whether route is still inside its learning period. The
// start time is the first stored live exchange on the route.
func (r *Recorder) Learning(ctx context.Context, route string) bool {
	r.mu.Lock()
	start, ok := r.started[route]
	r.mu.Unlock()
	if !ok {
		var ts string
		err := r.st.DB.QueryRowContext(ctx, `SELECT started_at FROM route_learning WHERE route = ?`, route).Scan(&ts)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return true // nothing recorded yet
		case err != nil:
			return false // fail closed: do not record when unsure
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return false
		}
		start = t
		r.mu.Lock()
		r.started[route] = start
		r.mu.Unlock()
	}
	return r.opt.Now().Before(start.Add(r.opt.LearningPeriod))
}

// Read decrypts one stored exchange.
func (r *Recorder) Read(ctx context.Context, id int64) (Record, error) {
	var route string
	var sealed []byte
	if err := r.st.DB.QueryRowContext(ctx, `SELECT route, sealed FROM corpus_exchanges WHERE id = ?`, id).Scan(&route, &sealed); err != nil {
		return Record{}, err
	}
	plain, err := r.sealer.Open(sealed, aadCorpus(route))
	if err != nil {
		return Record{}, fmt.Errorf("exchange %d: %w", id, err)
	}
	var rec Record
	err = json.Unmarshal(plain, &rec)
	return rec, err
}

// IDs lists stored exchange ids for a route, oldest first.
func (r *Recorder) IDs(ctx context.Context, route string) ([]int64, error) {
	rows, err := r.st.DB.QueryContext(ctx, `SELECT id FROM corpus_exchanges WHERE route = ? ORDER BY id`, route)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

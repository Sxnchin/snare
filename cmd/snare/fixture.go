package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sxnchin/snare/internal/artex"
	"github.com/Sxnchin/snare/internal/store"
)

// cmdFixture exports a finished ARTEX task into a fixture directory: the
// task, its outcome, every finding with its lineage, and the HTTP exchanges
// each finding is bound to. Responses are stored as ARTEX returned them
// (pretty-printed), so the connector can be tested against a fake ARTEX that
// serves exactly these documents.
//
//	snare fixture export -artex-url URL -password-file FILE -task ID -out DIR [-forbid FILE]...
func cmdFixture(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(stderr, "usage: snare fixture export -artex-url URL -password-file FILE -task ID -out DIR [-forbid FILE]")
		return 2
	}
	fs := flag.NewFlagSet("fixture export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("artex-url", "http://127.0.0.1:8787", "ARTEX API base URL")
	pwFile := fs.String("password-file", "", "file holding ARTEX's admin password")
	task := fs.Int64("task", 0, "ARTEX task id")
	out := fs.String("out", "", "output directory (created; must be empty or new)")
	var forbid multiFlag
	fs.Var(&forbid, "forbid", "file holding a secret that must not appear in any exported file (repeatable)")
	trafficHost := fs.String("artex-traffic-host", "", "also export ARTEX's own recorded exchanges to this host made while the task ran (artex_traffic.json)")
	capture := fs.String("capture", "", "Snare scanner capture (JSON Lines) of the same run: stored gzipped, and matched to each finding's evidence")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *pwFile == "" || *task <= 0 || *out == "" {
		fmt.Fprintln(stderr, "fixture export: -password-file, -task and -out are required")
		return 2
	}
	var secrets []string
	for _, f := range forbid {
		s, err := store.ReadSecret(f)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		secrets = append(secrets, s)
	}
	c := artex.New(*base, "ARTEX", func() (string, error) { return store.ReadSecret(*pwFile) }, 60*time.Second)
	files, err := exportTask(context.Background(), c, *task)
	if err != nil {
		fmt.Fprintln(stderr, "fixture export:", err)
		return 1
	}
	if *trafficHost != "" {
		if files["artex_traffic.json"], err = exportTraffic(context.Background(), c, files["task.json"], *trafficHost); err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
	}
	var gz []byte
	if *capture != "" {
		lines, raw, err := readCapture(*capture)
		if err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
		if err := matchEvidence(files, lines); err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
		for _, sec := range secrets {
			if bytes.Contains(raw, []byte(sec)) {
				fmt.Fprintln(stderr, "fixture export: the capture contains a forbidden secret; nothing written")
				return 1
			}
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Name = "scanner.jsonl"
		if _, err := zw.Write(raw); err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
		if err := zw.Close(); err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
		gz = buf.Bytes()
	}
	if err := writeFixture(*out, files, secrets); err != nil {
		fmt.Fprintln(stderr, "fixture export:", err)
		return 1
	}
	if gz != nil {
		if err := os.WriteFile(filepath.Join(*out, "scanner.jsonl.gz"), gz, 0o600); err != nil {
			fmt.Fprintln(stderr, "fixture export:", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "wrote %d files to %s\n", len(files), *out)
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// exportTask reads everything for one task. The result maps relative file
// names to their contents.
func exportTask(ctx context.Context, c *artex.Client, task int64) (map[string][]byte, error) {
	get := func(path string) (json.RawMessage, error) {
		var raw json.RawMessage
		if err := c.Authed(ctx, "GET", path, nil, &raw); err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
		return raw, nil
	}
	files := map[string][]byte{}
	id := strconv.FormatInt(task, 10)
	var err error
	if files["task.json"], err = get("/api/tasks/" + id); err != nil {
		return nil, err
	}
	if files["outcome.json"], err = get("/api/tasks/" + id + "/outcome"); err != nil {
		return nil, err
	}
	list, err := get("/api/exploration/findings?task=" + url.QueryEscape(id) + "&page=1&limit=200")
	if err != nil {
		return nil, err
	}
	ids, err := findingIDs(list)
	if err != nil {
		return nil, err
	}
	type findingDoc struct {
		Finding json.RawMessage `json:"finding"`
		Lineage json.RawMessage `json:"lineage"`
	}
	var findings []findingDoc
	for _, fid := range ids {
		f, err := get("/api/exploration/findings/" + fid)
		if err != nil {
			return nil, err
		}
		lin, err := get("/api/exploration/findings/" + fid + "/lineage")
		if err != nil {
			return nil, err
		}
		findings = append(findings, findingDoc{Finding: f, Lineage: lin})

		var bound struct {
			Bindings []struct {
				TrafficID string `json:"traffic_id"`
			} `json:"traffic_bindings"`
		}
		if err := json.Unmarshal(f, &bound); err != nil {
			return nil, fmt.Errorf("finding %s: %w", fid, err)
		}
		ev := evidenceDoc{FindingID: fid, ArtexBound: []boundExchange{}}
		for _, b := range bound.Bindings {
			ex, err := get("/api/traffic/exchange?id=" + url.QueryEscape(b.TrafficID))
			if err != nil {
				return nil, fmt.Errorf("finding %s: %w", fid, err)
			}
			ev.ArtexBound = append(ev.ArtexBound, boundExchange{TrafficID: b.TrafficID, Exchange: ex})
		}
		if files["evidence/"+fid+".json"], err = json.Marshal(ev); err != nil {
			return nil, err
		}
	}
	if files["findings.json"], err = json.Marshal(findings); err != nil {
		return nil, err
	}
	return files, nil
}

// findingIDs accepts the findings list as a bare array or wrapped in an
// object with an "items" or "findings" array, and returns the ids in
// numeric order.
func findingIDs(raw json.RawMessage) ([]string, error) {
	// "id" is the exploration node; "finding_id" is the finding record the
	// detail endpoints take. Older lists have only "id".
	type item struct {
		ID        json.RawMessage `json:"id"`
		FindingID json.RawMessage `json:"finding_id"`
	}
	var items []item
	if err := json.Unmarshal(raw, &items); err != nil {
		var wrapped struct {
			Items    []item `json:"items"`
			Findings []item `json:"findings"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 != nil {
			return nil, fmt.Errorf("findings list: %w", err)
		}
		items = append(wrapped.Items, wrapped.Findings...)
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		raw := it.FindingID
		if len(raw) == 0 || string(raw) == "null" || string(raw) == `""` {
			raw = it.ID
		}
		s := strings.Trim(string(raw), `"`)
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return nil, fmt.Errorf("findings list: bad id %s", it.ID)
		}
		ids = append(ids, s)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.ParseInt(ids[i], 10, 64)
		b, _ := strconv.ParseInt(ids[j], 10, 64)
		return a < b
	})
	return ids, nil
}

// writeFixture pretty-prints every file into dir. It refuses to write
// anything if a forbidden secret appears in any file, or if dir already
// holds files (fixtures are versioned, never edited in place).
func writeFixture(dir string, files map[string][]byte, secrets []string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty; fixtures are never overwritten, use a new version", dir)
	}
	pretty := make(map[string][]byte, len(files))
	for name, b := range files {
		var buf bytes.Buffer
		if err := json.Indent(&buf, b, "", "  "); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		buf.WriteByte('\n')
		for _, s := range secrets {
			if s != "" && bytes.Contains(buf.Bytes(), []byte(s)) {
				return fmt.Errorf("%s contains a forbidden secret; nothing written", name)
			}
		}
		pretty[name] = buf.Bytes()
	}
	names := make([]string, 0, len(pretty))
	for n := range pretty {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := filepath.Join(dir, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, pretty[n], 0o600); err != nil {
			return err
		}
	}
	return nil
}

// evidenceDoc is one evidence/<finding>.json file.
type evidenceDoc struct {
	FindingID string `json:"finding_id"`
	// ArtexBound are the exchanges ARTEX bound to the finding, as ARTEX
	// stored them.
	ArtexBound []boundExchange `json:"artex_bound"`
	// SnareMatched are lines of scanner.jsonl whose method and path appear
	// in the finding's evidence text. A heuristic, made by Snare, not by
	// ARTEX: use ArtexBound when it is present.
	SnareMatched []captureRef `json:"snare_matched,omitempty"`
	MatchRule    string       `json:"snare_match_rule,omitempty"`
}

type boundExchange struct {
	TrafficID string          `json:"traffic_id"`
	Exchange  json.RawMessage `json:"exchange"`
}

type captureRef struct {
	Line   int    `json:"line"` // 1-based line in scanner.jsonl
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Status int    `json:"status"`
}

type captureLine struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query"`
	Status int    `json:"status"`
}

func readCapture(path string) ([]captureLine, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var lines []captureLine
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		var l captureLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return nil, nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		lines = append(lines, l)
	}
	return lines, raw, sc.Err()
}

const matchRule = "a request line in the finding's evidence, summary or name (METHOD /path or METHOD http://host/path) with the same method and path as the captured request"

var reqLine = regexp.MustCompile(`\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(?:https?://[^/\s"'\\]+)?(/[^\s"'\\?#]*)`)

// matchEvidence adds SnareMatched to every evidence file from the capture.
func matchEvidence(files map[string][]byte, lines []captureLine) error {
	var findings []struct {
		Finding json.RawMessage `json:"finding"`
	}
	if err := json.Unmarshal(files["findings.json"], &findings); err != nil {
		return err
	}
	for _, f := range findings {
		var doc map[string]any
		if err := json.Unmarshal(f.Finding, &doc); err != nil {
			return err
		}
		fid := fmt.Sprint(doc["id"])
		text := fmt.Sprint(doc["evidence"], " ", doc["summary"], " ", doc["name"])
		want := map[string]bool{}
		for _, m := range reqLine.FindAllStringSubmatch(text, -1) {
			want[m[1]+" "+strings.TrimRight(m[2], ".,;:)")] = true
		}
		var ev evidenceDoc
		name := "evidence/" + fid + ".json"
		if err := json.Unmarshal(files[name], &ev); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		ev.SnareMatched = nil
		for i, l := range lines {
			if want[l.Method+" "+l.Path] {
				ev.SnareMatched = append(ev.SnareMatched, captureRef{Line: i + 1, Time: l.Time, Method: l.Method, Path: l.Path, Query: l.Query, Status: l.Status})
			}
		}
		ev.MatchRule = matchRule
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		files[name] = b
	}
	return nil
}

// exportTraffic returns ARTEX's recorded exchanges to host whose timestamp
// falls between the task's creation and completion (one-second resolution,
// as ARTEX records them), oldest first, each with its full request and
// response.
func exportTraffic(ctx context.Context, c *artex.Client, taskJSON []byte, host string) ([]byte, error) {
	var task struct {
		Created   int64 `json:"created_unix"`
		Completed int64 `json:"completed_unix"`
	}
	if err := json.Unmarshal(taskJSON, &task); err != nil {
		return nil, fmt.Errorf("task.json: %w", err)
	}
	if task.Created == 0 || task.Completed == 0 {
		return nil, errors.New("task has no creation or completion time; is it finished?")
	}
	type meta struct {
		ID string `json:"id"`
		TS string `json:"ts"`
	}
	var all []meta
	for page := 0; ; page++ {
		var resp struct {
			Total     int    `json:"total"`
			Exchanges []meta `json:"exchanges"`
		}
		path := fmt.Sprintf("/api/traffic?host=%s&page=%d&size=200&sort=ts&order=asc", url.QueryEscape(host), page)
		if err := c.Authed(ctx, "GET", path, nil, &resp); err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
		all = append(all, resp.Exchanges...)
		if len(resp.Exchanges) == 0 || len(all) >= resp.Total || page > 500 {
			break
		}
	}
	type exchangeDoc struct {
		TrafficID string          `json:"traffic_id"`
		TS        string          `json:"ts"`
		Exchange  json.RawMessage `json:"exchange"`
	}
	var out []exchangeDoc
	for _, m := range all {
		t, err := time.Parse(time.RFC3339, m.TS)
		if err != nil || t.Unix() < task.Created || t.Unix() > task.Completed {
			continue
		}
		var raw json.RawMessage
		if err := c.Authed(ctx, "GET", "/api/traffic/exchange?id="+url.QueryEscape(m.ID), nil, &raw); err != nil {
			return nil, fmt.Errorf("exchange %s: %w", m.ID, err)
		}
		out = append(out, exchangeDoc{TrafficID: m.ID, TS: m.TS, Exchange: raw})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS < out[j].TS })
	return json.Marshal(out)
}

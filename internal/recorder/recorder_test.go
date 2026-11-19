package recorder

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newRecorder(t *testing.T, period time.Duration, c *clock) (*Recorder, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "s.db")
	st := openStore(t, dbPath)
	sealer, err := LoadSealer(context.Background(), st, "", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{LearningPeriod: period, MaxBodyBytes: 1 << 16, QueueSize: 4}
	if c != nil {
		opt.Now = c.now
	}
	return New(st, sealer, NewRedactor(nil, nil), opt), dbPath
}

func gz(_ *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func loginExchange(t *testing.T) Exchange {
	reqH := http.Header{}
	reqH.Set("Content-Type", "application/json")
	reqH.Set("Cookie", "token="+testJWT+"; language=en")
	respH := http.Header{}
	respH.Set("Content-Type", "application/json; charset=utf-8")
	respH.Set("Content-Encoding", "gzip")
	respH.Set("Set-Cookie", "token="+testJWT+"; Path=/")
	return Exchange{
		Route: "shop", Method: "POST", Host: "shop.lab", Path: "/rest/user/login", RawQuery: "next=%2F",
		ReqHeader: reqH, ReqBody: []byte(`{"email":"` + testEmail + `","password":"hunter2-Secret"}`),
		Status: 200, RespHeader: respH,
		RespBody: gz(t, `{"authentication":{"token":"`+testJWT+`","bid":3,"umail":"`+testEmail+`"}}`),
		Duration: 12 * time.Millisecond,
	}
}

func TestStoreRedactsAndEncrypts(t *testing.T) {
	ctx := context.Background()
	rec, dbPath := newRecorder(t, time.Hour, nil)
	if err := rec.Store(ctx, loginExchange(t)); err != nil {
		t.Fatal(err)
	}
	ids, err := rec.IDs(ctx, "shop")
	if err != nil || len(ids) != 1 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}
	r, err := rec.Read(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Path != "/rest/user/login" || r.Status != 200 {
		t.Fatalf("record: %+v", r)
	}
	// The gzip body was decoded and parsed as JSON: the key is visible and
	// the sensitive object under it is replaced whole.
	if r.RespBody != `{"authentication":"[REDACTED:field]"}` {
		t.Fatalf("gzip response not decoded before redaction: %q", r.RespBody)
	}
	all := r.ReqBody + r.RespBody + strings.Join(r.ReqHeaders["Cookie"], "") + strings.Join(r.RespHeaders["Set-Cookie"], "")
	for _, s := range []string{testJWT, testEmail, "hunter2-Secret"} {
		if strings.Contains(all, s) {
			t.Errorf("decrypted record still contains %q", s)
		}
	}

	// Nothing sensitive, redacted or not, is readable in the database file.
	rec.st.Close()
	raw := readAll(t, dbPath)
	for _, s := range []string{testJWT, testEmail, "hunter2-Secret", "bid", "authentication"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("database file contains plaintext %q", s)
		}
	}
}

func readAll(_ *testing.T, dbPath string) []byte {
	var out []byte
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(dbPath + suffix)
		if err == nil {
			out = append(out, b...)
		}
	}
	return out
}

func TestUndecodableEncodingIsNotStored(t *testing.T) {
	ctx := context.Background()
	rec, _ := newRecorder(t, time.Hour, nil)
	ex := loginExchange(t)
	ex.RespHeader.Set("Content-Encoding", "br")
	ex.RespBody = []byte("raw brotli bytes with " + testEmail)
	if err := rec.Store(ctx, ex); err != nil {
		t.Fatal(err)
	}
	ids, _ := rec.IDs(ctx, "shop")
	r, _ := rec.Read(ctx, ids[0])
	if r.RespBody != placeholder(KindBinary) {
		t.Fatalf("undecodable body stored: %q", r.RespBody)
	}
}

func TestLearningPeriod(t *testing.T) {
	ctx := context.Background()
	c := &clock{t: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
	rec, _ := newRecorder(t, 72*time.Hour, c)
	if !rec.Learning(ctx, "shop") {
		t.Fatal("a route with no corpus is learning")
	}
	ex := loginExchange(t)
	ex.Time = c.t
	if err := rec.Store(ctx, ex); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(71 * time.Hour)
	if !rec.Learning(ctx, "shop") {
		t.Fatal("still inside the learning period")
	}
	c.t = c.t.Add(2 * time.Hour)
	if rec.Learning(ctx, "shop") {
		t.Fatal("learning period should have ended")
	}
	// HAR imports do not start the learning clock.
	har := loginExchange(t)
	har.Route, har.Source = "other", SourceHAR
	if err := rec.Store(ctx, har); err != nil {
		t.Fatal(err)
	}
	if rec.LearningEnds(ctx, "other") != (time.Time{}) {
		t.Fatal("HAR import must not start the learning period")
	}
}

func TestSubmitNeverBlocks(t *testing.T) {
	rec, _ := newRecorder(t, time.Hour, nil) // queue size 4, writer not running
	ex := loginExchange(t)
	accepted := 0
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			if rec.Submit(ex) {
				accepted++
			}
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked")
	}
	if _, dropped := rec.Stats(); accepted != 4 || dropped != 6 {
		t.Fatalf("accepted=%d dropped=%d", accepted, dropped)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run drains the queue and returns
	rec.Run(ctx)
	if stored, _ := rec.Stats(); stored != 4 {
		t.Fatalf("stored=%d after drain", stored)
	}
}

func TestCoverage(t *testing.T) {
	ctx := context.Background()
	rec, _ := newRecorder(t, time.Hour, nil)
	for _, p := range []string{"/api/Products/1", "/api/Products/22", "/rest/products/search"} {
		ex := loginExchange(t)
		ex.Method, ex.Path, ex.RawQuery, ex.ReqBody = "GET", p, "q=apple", nil
		ex.ReqHeader = http.Header{}
		if err := rec.Store(ctx, ex); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Store(ctx, loginExchange(t)); err != nil {
		t.Fatal(err)
	}
	cov, err := rec.Coverage(ctx, []string{"shop", "empty-route"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov) != 2 || cov[0].Route != "empty-route" || cov[0].Requests != 0 {
		t.Fatalf("routes: %+v", cov)
	}
	shop := cov[1]
	if shop.Requests != 4 || shop.Methods["GET"] != 3 || shop.Methods["POST"] != 1 {
		t.Fatalf("shop: %+v", shop)
	}
	byPath := map[string]EndpointCoverage{}
	for _, e := range shop.Endpoints {
		byPath[e.Method+" "+e.Path] = e
	}
	if e := byPath["GET /api/Products/{n}"]; e.Requests != 2 || e.Statuses["2xx"] != 2 {
		t.Fatalf("templated endpoint: %+v (all: %v)", e, byPath)
	}
	login := byPath["POST /rest/user/login"]
	if strings.Join(login.Params, ",") != "json:email,json:password,query:next" {
		t.Fatalf("login params: %v", login.Params)
	}
}

func TestPathTemplate(t *testing.T) {
	for in, want := range map[string]string{
		"/api/Products/12":                               "/api/Products/{n}",
		"/rest/basket/3/checkout":                        "/rest/basket/{n}/checkout",
		"/x/550e8400-e29b-41d4-a716-446655440000":        "/x/{id}",
		"/x/d41d8cd98f00b204e9800998ecf8427e":            "/x/{id}",
		"/u/[REDACTED:email]/profile":                    "/u/{redacted}/profile",
		"/assets/public/images/products/apple_juice.jpg": "/assets/public/images/products/apple_juice.jpg",
		"/": "/",
		"/rest/track-order/2641-64d2ab16ce8b49ee": "/rest/track-order/{id}",
		"/rest/track-order/deadbeef-cafe":         "/rest/track-order/deadbeef-cafe", // no digit: a word, not an id
	} {
		if got := PathTemplate(in); got != want {
			t.Errorf("PathTemplate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImportHAR(t *testing.T) {
	ctx := context.Background()
	rec, _ := newRecorder(t, time.Hour, nil)
	har := `{"log":{"entries":[
	 {"startedDateTime":"2026-11-18T10:00:00.000Z","time":5,
	  "request":{"method":"POST","url":"http://shop.lab:8000/rest/user/login?x=1",
	   "headers":[{"name":":authority","value":"shop.lab"},{"name":"Content-Type","value":"application/json"},{"name":"Cookie","value":"token=` + testJWT + `"}],
	   "postData":{"mimeType":"application/json","text":"{\"email\":\"` + testEmail + `\",\"password\":\"pw-Secret-1\"}"}},
	  "response":{"status":200,"headers":[{"name":"Content-Encoding","value":"gzip"}],
	   "content":{"size":40,"mimeType":"application/json","text":"eyJvayI6dHJ1ZX0=","encoding":"base64"}}},
	 {"startedDateTime":"2026-11-18T10:00:01.000Z","time":1,
	  "request":{"method":"GET","url":"https://fonts.example.net/font.woff2","headers":[]},
	  "response":{"status":200,"headers":[],"content":{"size":0,"mimeType":"font/woff2"}}},
	 {"startedDateTime":"2026-11-18T10:00:02.000Z","time":0,
	  "request":{"method":"GET","url":"http://shop.lab:8000/blocked","headers":[]},
	  "response":{"status":0,"headers":[],"content":{"size":0}}}
	]}}`
	res, err := rec.ImportHAR(ctx, "shop", []string{"shop.lab"}, strings.NewReader(har))
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 || res.Skipped != 2 {
		t.Fatalf("result: %+v", res)
	}
	ids, _ := rec.IDs(ctx, "shop")
	r, err := rec.Read(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if r.RespBody != `{"ok":true}` {
		t.Fatalf("base64 HAR body: %q", r.RespBody)
	}
	if _, ok := r.ReqHeaders[":authority"]; ok {
		t.Fatal("pseudo-header imported")
	}
	for _, s := range []string{testJWT, testEmail, "pw-Secret-1"} {
		if strings.Contains(r.ReqBody+strings.Join(r.ReqHeaders["Cookie"], ""), s) {
			t.Errorf("HAR import kept %q", s)
		}
	}
	if _, err := rec.ImportHAR(ctx, "shop", nil, strings.NewReader("not json")); err == nil {
		t.Fatal("bad HAR accepted")
	}
}

package recorder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HAR 1.2, only the fields the importer uses.
type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	StartedDateTime string  `json:"startedDateTime"`
	Time            float64 `json:"time"`
	Request         struct {
		Method   string      `json:"method"`
		URL      string      `json:"url"`
		Headers  []harHeader `json:"headers"`
		PostData *struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
		} `json:"postData"`
	} `json:"request"`
	Response struct {
		Status  int         `json:"status"`
		Headers []harHeader `json:"headers"`
		Content struct {
			Size     int64  `json:"size"`
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARResult reports what an import did.
type HARResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Reasons  []string `json:"reasons,omitempty"` // first few skip reasons
}

// ImportHAR reads a HAR document and stores its entries for route. Only
// entries whose URL host matches one of hosts are imported (empty hosts
// accepts all), so a HAR captured in a browser does not pull in third-party
// requests. HTTP/2 pseudo-headers are dropped. Bodies go through the same
// redaction as live traffic.
func (r *Recorder) ImportHAR(ctx context.Context, route string, hosts []string, rd io.Reader) (HARResult, error) {
	var h harFile
	dec := json.NewDecoder(io.LimitReader(rd, 512<<20))
	if err := dec.Decode(&h); err != nil {
		return HARResult{}, fmt.Errorf("parse HAR: %w", err)
	}
	allowed := map[string]bool{}
	for _, host := range hosts {
		allowed[strings.ToLower(host)] = true
	}
	var res HARResult
	skip := func(reason string) {
		res.Skipped++
		if len(res.Reasons) < 10 {
			res.Reasons = append(res.Reasons, reason)
		}
	}
	for i, e := range h.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host == "" {
			skip(fmt.Sprintf("entry %d: bad URL", i))
			continue
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(u.Host)] && !allowed[strings.ToLower(u.Hostname())] {
			skip(fmt.Sprintf("entry %d: host %s not in -host list", i, u.Host))
			continue
		}
		if e.Response.Status == 0 {
			skip(fmt.Sprintf("entry %d: no response (aborted or blocked)", i))
			continue
		}
		ex := Exchange{
			Route:      route,
			Source:     SourceHAR,
			Duration:   time.Duration(e.Time * float64(time.Millisecond)),
			Method:     e.Request.Method,
			Host:       u.Host,
			Path:       u.EscapedPath(),
			RawQuery:   u.RawQuery,
			ReqHeader:  harHeaders(e.Request.Headers),
			Status:     e.Response.Status,
			RespHeader: harHeaders(e.Response.Headers),
		}
		if t, err := time.Parse(time.RFC3339Nano, e.StartedDateTime); err == nil {
			ex.Time = t
		}
		if ex.Path == "" {
			ex.Path = "/"
		}
		if pd := e.Request.PostData; pd != nil {
			ex.ReqBody = []byte(pd.Text)
			if ex.ReqHeader.Get("Content-Type") == "" && pd.MimeType != "" {
				ex.ReqHeader.Set("Content-Type", pd.MimeType)
			}
		}
		body := []byte(e.Response.Content.Text)
		if e.Response.Content.Encoding == "base64" {
			if b, err := base64.StdEncoding.DecodeString(e.Response.Content.Text); err == nil {
				body = b
			}
		}
		// HAR content is already decoded; drop Content-Encoding so the
		// recorder does not try to decompress it again.
		ex.RespHeader.Del("Content-Encoding")
		if ex.RespHeader.Get("Content-Type") == "" && e.Response.Content.MimeType != "" {
			ex.RespHeader.Set("Content-Type", e.Response.Content.MimeType)
		}
		limit := r.opt.MaxBodyBytes
		ex.ReqBodyBytes, ex.RespBodyBytes = int64(len(ex.ReqBody)), int64(len(body))
		if e.Response.Content.Size > ex.RespBodyBytes {
			ex.RespBodyBytes = e.Response.Content.Size
		}
		if len(ex.ReqBody) > limit {
			ex.ReqBody = ex.ReqBody[:limit]
		}
		if len(body) > limit {
			body = body[:limit]
		}
		ex.RespBody = body
		if err := r.Store(ctx, ex); err != nil {
			return res, fmt.Errorf("entry %d: %w", i, err)
		}
		res.Imported++
	}
	return res, nil
}

func harHeaders(in []harHeader) http.Header {
	h := http.Header{}
	for _, kv := range in {
		if strings.HasPrefix(kv.Name, ":") {
			continue
		}
		h.Add(kv.Name, kv.Value)
	}
	return h
}

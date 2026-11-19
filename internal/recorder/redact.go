package recorder

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Placeholder kinds. A redacted value becomes "[REDACTED:<kind>]".
const (
	KindHeader = "header"
	KindField  = "field"
	KindEmail  = "email"
	KindCard   = "card"
	KindJWT    = "jwt"
	KindAPIKey = "apikey"
	KindBearer = "bearer"
	KindBinary = "binary"
)

func placeholder(kind string) string { return "[REDACTED:" + kind + "]" }

// Redactor removes credentials and personal data from recorded traffic before
// it is stored. It is deterministic and safe for concurrent use.
//
// What it removes:
//   - header values: Authorization, Proxy-Authorization, Cookie and
//     Set-Cookie values (cookie names are kept, because cookie continuity
//     matters to the detector), plus configured headers;
//   - values of sensitive fields in JSON bodies, form bodies and query
//     strings: built-in names such as password or token, plus configured ones;
//   - anywhere in text (paths, query values, bodies, other headers): email
//     addresses, card-like numbers that pass the Luhn check, JWTs, bearer
//     tokens, and API-key-like strings.
type Redactor struct {
	headers map[string]bool // canonical header names whose values are dropped
	fields  map[string]bool // normalized field names whose values are dropped
}

var builtinHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
	"X-Api-Key", "X-Auth-Token", "X-Csrf-Token", "X-Xsrf-Token",
}

// Field names are compared after normalizeField, so "Pass_Word", "passWord"
// and "password" are the same.
var builtinFields = []string{
	"password", "passwd", "pwd", "passwordrepeat", "newpassword", "currentpassword",
	"secret", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken",
	"authentication", "authorization", "auth", "apikey", "key", "privatekey",
	"session", "sessionid", "sid", "csrf", "xsrf", "otp", "totp", "totpsecret",
	"securityanswer", "answer", "cvv", "cvc", "cardnumber", "cardnum", "ccnumber", "iban",
	"ssn",
	// Personal data. Generic names such as "name" or "city" are left out on
	// purpose: they would also wipe product names and other content the
	// corpus needs. Add more with recorder.redact.json_fields.
	"fullname", "firstname", "lastname", "surname", "displayname",
	"phone", "phonenumber", "mobile", "mobilenum", "mobilenumber",
	"address", "streetaddress", "street", "zipcode", "postalcode", "postcode",
	"dob", "dateofbirth", "birthdate",
}

// NewRedactor builds a redactor with the built-in rules plus extra headers
// and JSON/form/query field names.
func NewRedactor(extraHeaders, extraFields []string) *Redactor {
	r := &Redactor{headers: map[string]bool{}, fields: map[string]bool{}}
	for _, h := range append(append([]string{}, builtinHeaders...), extraHeaders...) {
		r.headers[http.CanonicalHeaderKey(strings.TrimSpace(h))] = true
	}
	for _, f := range append(append([]string{}, builtinFields...), extraFields...) {
		if n := normalizeField(f); n != "" {
			r.fields[n] = true
		}
	}
	return r
}

func normalizeField(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// SensitiveField reports whether a field name's value is always dropped.
func (r *Redactor) SensitiveField(name string) bool {
	return r.fields[normalizeField(name)]
}

var (
	reJWT    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	reBearer = regexp.MustCompile(`(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}`)
	reEmail  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// Known credential prefixes, then AWS access key IDs.
	reKnownKey = regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{16,}|sk_(live|test)_[A-Za-z0-9]{16,}|pk_(live|test)_[A-Za-z0-9]{16,}|rk_(live|test)_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|(AKIA|ASIA)[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20,})`)
	// Generic: a long token mixing letters and digits. Candidates are
	// checked by looksLikeKey to skip words, UUIDs and plain hex hashes.
	reLongToken = regexp.MustCompile(`[A-Za-z0-9_\-+/]{32,}={0,2}`)
	// Card-like: 13 to 19 digits, optionally grouped by spaces or dashes.
	reCard = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	// Already-redacted placeholders are left alone.
	rePlaceholder = regexp.MustCompile(`\[REDACTED:[a-z]+\]`)
)

// Text redacts detectors' matches anywhere in s.
func (r *Redactor) Text(s string) string { return r.text(s, true) }

// textStrict runs every detector except the generic long-token one. It is
// used where long mixed-case tokens are normal and not secret: ETag headers
// and CSS or JavaScript bodies (minified code, data URIs). Known key
// formats, JWTs, emails and cards are still caught there.
func (r *Redactor) textStrict(s string) string { return r.text(s, false) }

func (r *Redactor) text(s string, generic bool) string {
	if s == "" {
		return s
	}
	s = reJWT.ReplaceAllLiteralString(s, placeholder(KindJWT))
	s = reBearer.ReplaceAllStringFunc(s, func(m string) string {
		scheme := m[:strings.IndexAny(m, " \t")]
		return scheme + " " + placeholder(KindBearer)
	})
	s = reKnownKey.ReplaceAllLiteralString(s, placeholder(KindAPIKey))
	s = reEmail.ReplaceAllLiteralString(s, placeholder(KindEmail))
	s = reCard.ReplaceAllStringFunc(s, func(m string) string {
		if cardLike(m) {
			return placeholder(KindCard)
		}
		return m
	})
	if generic {
		s = reLongToken.ReplaceAllStringFunc(s, func(m string) string {
			if looksLikeKey(m) {
				return placeholder(KindAPIKey)
			}
			return m
		})
	}
	return s
}

// validatorHeaders carry opaque cache validators, not credentials.
var validatorHeaders = map[string]bool{"Etag": true, "If-None-Match": true, "If-Match": true}

// cardLike reports whether a run of digit groups (split on spaces and
// dashes) contains a Luhn-valid card number made of whole consecutive groups.
// Checking whole groups catches a card with a stray number next to it
// ("4111 1111 1111 1111 0") without testing every digit window, which would
// flag most long numeric identifiers.
func cardLike(m string) bool {
	groups := strings.FieldsFunc(m, func(r rune) bool { return r == ' ' || r == '-' })
	for i := range groups {
		n := 0
		for j := i; j < len(groups); j++ {
			n += len(groups[j])
			if n > 19 {
				break
			}
			if n >= 13 && luhn(strings.Join(groups[i:j+1], "")) {
				return true
			}
		}
	}
	return false
}

func luhn(s string) bool {
	sum, n, alt := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		d := int(c - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		n++
		alt = !alt
	}
	return n >= 13 && sum%10 == 0
}

// looksLikeKey accepts a long token that mixes upper case, lower case and
// digits. Plain hex (hashes, ids), all-lower words and paths are left alone,
// because they are common and rarely secret; known credential formats are
// caught by reKnownKey instead.
func looksLikeKey(s string) bool {
	if strings.Count(s, "/") > 2 {
		return false // a path, not a key
	}
	var up, lo, dig int
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			up++
		case c >= 'a' && c <= 'z':
			lo++
		case c >= '0' && c <= '9':
			dig++
		}
	}
	return up > 0 && lo > 0 && dig > 0
}

// Headers returns a redacted copy of h.
func (r *Redactor) Headers(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		for _, v := range vs {
			switch {
			case ck == "Cookie":
				out[ck] = append(out[ck], redactCookieHeader(v))
			case ck == "Set-Cookie":
				out[ck] = append(out[ck], redactSetCookie(v))
			case r.headers[ck]:
				out[ck] = append(out[ck], placeholder(KindHeader))
			case validatorHeaders[ck]:
				out[ck] = append(out[ck], r.textStrict(v))
			default:
				out[ck] = append(out[ck], r.Text(v))
			}
		}
	}
	return out
}

// redactCookieHeader keeps cookie names and drops every value.
func redactCookieHeader(v string) string {
	parts := strings.Split(v, ";")
	for i, p := range parts {
		name, _, _ := strings.Cut(strings.TrimSpace(p), "=")
		parts[i] = name + "=" + placeholder(KindHeader)
	}
	return strings.Join(parts, "; ")
}

// redactSetCookie keeps the cookie name and attributes and drops the value.
func redactSetCookie(v string) string {
	first, rest, hasRest := strings.Cut(v, ";")
	name, _, _ := strings.Cut(strings.TrimSpace(first), "=")
	out := name + "=" + placeholder(KindHeader)
	if hasRest {
		out += ";" + rest
	}
	return out
}

// Query redacts a raw query string: sensitive parameter names lose their
// values, other values go through the text detectors. It also returns the
// parameter names seen, sorted and deduplicated.
func (r *Redactor) Query(raw string) (string, []string) {
	if raw == "" {
		return "", nil
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		// Unparseable: keep nothing structural, redact as text.
		return r.Text(raw), nil
	}
	names := make([]string, 0, len(vals))
	for k, vs := range vals {
		names = append(names, k)
		for i, v := range vs {
			if r.SensitiveField(k) {
				vs[i] = placeholder(KindField)
			} else {
				vs[i] = r.Text(v)
			}
		}
	}
	sort.Strings(names)
	return encodeQuery(vals), names
}

// encodeQuery is url.Values.Encode without escaping the placeholder
// brackets, so redacted values stay readable.
func encodeQuery(v url.Values) string {
	enc := v.Encode()
	enc = strings.ReplaceAll(enc, "%5BREDACTED%3A", "[REDACTED:")
	return strings.ReplaceAll(enc, "%5D", "]")
}

// Path redacts a URL path segment by segment.
func (r *Redactor) Path(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		dec, err := url.PathUnescape(s)
		if err != nil {
			dec = s
		}
		red := r.Text(dec)
		if red != dec {
			segs[i] = red
		}
	}
	return strings.Join(segs, "/")
}

// Body redacts a body by content type. It returns the redacted text and the
// field names seen (JSON paths as "a.b", form names as plain names).
// Binary content is replaced by a placeholder; its length is kept by the
// caller.
func (r *Redactor) Body(contentType string, body []byte) (string, []string) {
	if len(body) == 0 {
		return "", nil
	}
	mt, _, _ := mime.ParseMediaType(contentType)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return r.Query(string(body))
	case strings.HasSuffix(mt, "json") || (mt == "" && looksJSON(body)):
		if out, names, ok := r.JSON(body); ok {
			return out, names
		}
		return r.Text(string(body)), nil
	case mt == "text/css" || strings.HasSuffix(mt, "javascript"):
		return r.textStrict(string(body)), nil
	case isTextual(mt, body):
		return r.Text(string(body)), nil
	default:
		return placeholder(KindBinary), nil
	}
}

// trimPartialRune drops a UTF-8 sequence cut off at the end of a sample.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		if r, _ := utf8.DecodeLastRune(b); r != utf8.RuneError {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

func looksJSON(b []byte) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func isTextual(mt string, body []byte) bool {
	switch {
	case strings.HasPrefix(mt, "text/"),
		strings.HasSuffix(mt, "xml"),
		strings.HasSuffix(mt, "javascript"),
		mt == "application/graphql":
		return true
	case mt == "":
		// Unknown type: treat as text only when it has no NUL bytes and is
		// valid UTF-8 in the sampled prefix.
		sample := body
		if len(sample) > 512 {
			sample = sample[:512]
		}
		return !bytes.ContainsRune(sample, 0) && utf8.Valid(trimPartialRune(sample))
	}
	return false
}

// JSON redacts a JSON document. ok is false when body is not valid JSON.
func (r *Redactor) JSON(body []byte) (string, []string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", nil, false
	}
	seen := map[string]bool{}
	v = r.walk(v, "", seen)
	out, err := json.Marshal(v)
	if err != nil {
		return "", nil, false
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	return string(out), names, true
}

func (r *Redactor) walk(v any, path string, seen map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if len(seen) < 256 {
				seen[p] = true
			}
			if r.SensitiveField(k) {
				if child != nil {
					t[k] = placeholder(KindField)
				}
				continue
			}
			t[k] = r.walk(child, p, seen)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = r.walk(child, path+"[]", seen)
		}
		return t
	case string:
		return r.Text(t)
	case json.Number:
		// Long digit runs in numbers can be card numbers.
		if s := t.String(); len(s) >= 13 && r.Text(s) != s {
			return placeholder(KindCard)
		}
		return t
	default:
		return t
	}
}

// IsRedacted reports whether s is exactly a placeholder.
func IsRedacted(s string) bool {
	return rePlaceholder.MatchString(s) && len(rePlaceholder.FindString(s)) == len(s)
}

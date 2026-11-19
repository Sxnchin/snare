package recorder

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Test values. Card numbers are well-known test numbers; keys are fake.
const (
	testJWT   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" // gitleaks:allow (the public jwt.io example token)
	testEmail = "alice.smith+test@example.co.uk"
	testCard  = "4111 1111 1111 1111"
	testAWS   = "AKIAIOSFODNN7EXAMPLE"
	testSK    = "sk-proj-abcdefghijklmnop1234567890"
)

func TestTextDetectors(t *testing.T) {
	r := NewRedactor(nil, nil)
	cases := []struct {
		in, secret, kind string
	}{
		{"token is " + testJWT + " ok", testJWT, KindJWT},
		{"mail " + testEmail + ".", testEmail, KindEmail},
		{"card " + testCard + " exp", testCard, KindCard},
		{"card 4111-1111-1111-1111", "4111-1111-1111-1111", KindCard},
		{"qty 2 4111 1111 1111 1111 0", "4111 1111 1111 1111", KindCard}, // stray digits around a card
		{"key=" + testAWS, testAWS, KindAPIKey},
		{"openai " + testSK, testSK, KindAPIKey},
		{"Authorization: Bearer abcdef1234567890", "abcdef1234567890", KindBearer},
		{"x Q2hhbmdlTWVQbGVhc2VUaGlzSXNBU2VjcmV0S2V5MTIz y", "Q2hhbmdlTWVQbGVhc2VUaGlzSXNBU2VjcmV0S2V5MTIz", KindAPIKey},
	}
	for _, c := range cases {
		out := r.Text(c.in)
		if strings.Contains(out, c.secret) {
			t.Errorf("%q: secret survived: %q", c.in, out)
		}
		if !strings.Contains(out, placeholder(c.kind)) {
			t.Errorf("%q: want %s placeholder, got %q", c.in, c.kind, out)
		}
	}
}

func TestTextLeavesOrdinaryContentAlone(t *testing.T) {
	r := NewRedactor(nil, nil)
	for _, s := range []string{
		"/rest/products/search?q=apple",
		"1234567890123",                        // 13 digits, fails Luhn
		"d41d8cd98f00b204e9800998ecf8427e",     // md5 hex: id-like, not secret
		"550e8400-e29b-41d4-a716-446655440000", // UUID
		"/assets/public/images/products/apple_juice.jpg",
		"Welcome to OWASP Juice Shop!",
		"order total 12.99 EUR on 2026-11-18",
	} {
		if out := r.Text(s); out != s {
			t.Errorf("over-redacted %q -> %q", s, out)
		}
	}
}

func TestHeaders(t *testing.T) {
	r := NewRedactor([]string{"X-Custom-Secret"}, nil)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+testJWT)
	h.Add("Cookie", "token="+testJWT+"; language=en; welcomebanner_status=dismiss")
	h.Add("Set-Cookie", "token="+testJWT+"; Path=/; HttpOnly")
	h.Set("X-Custom-Secret", "hunter2")
	h.Set("User-Agent", "Mozilla/5.0")
	h.Set("X-Contact", testEmail)
	out := r.Headers(h)
	flat, _ := json.Marshal(out)
	for _, secret := range []string{testJWT, "hunter2", testEmail, "=en", "=dismiss"} {
		if strings.Contains(string(flat), secret) {
			t.Errorf("header secret %q survived: %s", secret, flat)
		}
	}
	if got := out.Get("Cookie"); !strings.Contains(got, "token=") || !strings.Contains(got, "language=") {
		t.Errorf("cookie names must be kept: %q", got)
	}
	if got := out.Get("Set-Cookie"); !strings.HasPrefix(got, "token=[REDACTED:header]") || !strings.Contains(got, "HttpOnly") {
		t.Errorf("set-cookie: %q", got)
	}
	if out.Get("User-Agent") != "Mozilla/5.0" {
		t.Errorf("ordinary header changed: %q", out.Get("User-Agent"))
	}
}

func TestQueryAndForm(t *testing.T) {
	r := NewRedactor(nil, []string{"pin"})
	q, names := r.Query("q=apple&password=hunter2&email=" + url.QueryEscape(testEmail) + "&PIN=1234")
	for _, secret := range []string{"hunter2", "alice.smith", "1234"} {
		if strings.Contains(q, secret) {
			t.Errorf("query secret %q survived: %s", secret, q)
		}
	}
	if !strings.Contains(q, "q=apple") {
		t.Errorf("ordinary param changed: %s", q)
	}
	if strings.Join(names, ",") != "PIN,email,password,q" {
		t.Errorf("names = %v", names)
	}
	body, _ := r.Body("application/x-www-form-urlencoded", []byte("imageUrl=http%3A%2F%2Fx&token=abc"))
	if strings.Contains(body, "abc") || !strings.Contains(body, "imageUrl=") {
		t.Errorf("form body: %s", body)
	}
}

func TestJSONBody(t *testing.T) {
	r := NewRedactor(nil, []string{"loyaltyNumber"})
	in := `{"email":"` + testEmail + `","password":"hunter2","passwordRepeat":"hunter2",
	"securityAnswer":"Fluffy","authentication":{"token":"` + testJWT + `","bid":7,"umail":"` + testEmail + `"},
	"loyalty_number":"LN-99","card":4111111111111111,"items":[{"name":"Apple Juice","qty":2}],"empty":null}`
	out, names, ok := r.JSON([]byte(in))
	if !ok {
		t.Fatal("valid JSON rejected")
	}
	for _, secret := range []string{"alice.smith", "hunter2", "Fluffy", testJWT, "LN-99", "4111111111111111"} {
		if strings.Contains(out, secret) {
			t.Errorf("JSON secret %q survived: %s", secret, out)
		}
	}
	if !strings.Contains(out, "Apple Juice") || !strings.Contains(out, `"empty":null`) {
		t.Errorf("ordinary content changed: %s", out)
	}
	want := map[string]bool{"email": true, "password": true, "authentication": true, "items": true, "items[].name": true}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("field name %q not reported; got %v", w, names)
		}
	}
	// Field names under a redacted object are not walked.
	if got["authentication.token"] {
		t.Errorf("names under a redacted field leaked structure: %v", names)
	}
}

func TestBodyTypes(t *testing.T) {
	r := NewRedactor(nil, nil)
	if out, _ := r.Body("image/png", []byte{0x89, 'P', 'N', 'G', 0, 0}); out != placeholder(KindBinary) {
		t.Errorf("binary body = %q", out)
	}
	if out, _ := r.Body("text/html; charset=utf-8", []byte("<p>"+testEmail+"</p>")); strings.Contains(out, testEmail) {
		t.Errorf("html body kept email: %q", out)
	}
	if out, _ := r.Body("", []byte(`{"password":"x"}`)); strings.Contains(out, `"x"`) {
		t.Errorf("untyped JSON body not parsed: %q", out)
	}
	if out, _ := r.Body("application/json", []byte(`{"password": "trunc`)); strings.Contains(out, "trunc") && !strings.Contains(out, "password") {
		t.Errorf("truncated JSON: %q", out)
	}
}

func TestPath(t *testing.T) {
	r := NewRedactor(nil, nil)
	out := r.Path("/rest/user/" + testEmail + "/basket/6")
	if strings.Contains(out, testEmail) || !strings.HasSuffix(out, "/basket/6") {
		t.Errorf("path = %q", out)
	}
}

func TestIdempotent(t *testing.T) {
	r := NewRedactor(nil, nil)
	in := "a " + testJWT + " b " + testEmail + " c " + testCard + " d " + testAWS
	once := r.Text(in)
	if twice := r.Text(once); twice != once {
		t.Fatalf("not idempotent:\n%q\n%q", once, twice)
	}
}

// FuzzText checks that the text redactor never panics, is idempotent, and
// never lets a planted secret through, whatever surrounds it.
func FuzzText(f *testing.F) {
	for _, s := range []string{"", "hello", "a@b", "eyJ", "4111", "[REDACTED:email]", "Bearer ", "\x00\xff", "AKIA"} {
		f.Add(s, s)
	}
	r := NewRedactor(nil, nil)
	secrets := []string{testJWT, testEmail, testAWS, testSK, "4111111111111111"}
	f.Fuzz(func(t *testing.T, a, b string) {
		out := r.Text(a)
		if r.Text(out) != out {
			t.Fatalf("not idempotent for %q", a)
		}
		for _, s := range secrets {
			in := a + " " + s + " " + b
			if got := r.Text(in); strings.Contains(got, s) {
				t.Fatalf("planted %q survived in %q", s, got)
			}
		}
	})
}

// FuzzJSON checks that arbitrary bodies never panic the body redactor and
// that a planted password value never survives in valid JSON.
func FuzzJSON(f *testing.F) {
	f.Add([]byte(`{"a":1}`), "x")
	f.Add([]byte(`[{"password":"p"}]`), "y")
	f.Add([]byte(`{"nested":{"deep":[1,2,{"k":"v"}]}}`), "z")
	r := NewRedactor(nil, nil)
	f.Fuzz(func(t *testing.T, body []byte, key string) {
		_, _ = r.Body("application/json", body)
		_, _ = r.Body("", body)
		_, _ = r.Body("application/x-www-form-urlencoded", body)
		planted, _ := json.Marshal(map[string]any{"password": "PlantedSecret-9f3a", "other": key, "nested": map[string]any{"token": "PlantedSecret-9f3a"}}) // gitleaks:allow (planted fake value)
		out, _, ok := r.JSON(planted)
		if !ok || strings.Contains(out, "PlantedSecret-9f3a") {
			t.Fatalf("planted secret survived: %s", out)
		}
	})
}

func TestPersonalDataFields(t *testing.T) {
	r := NewRedactor(nil, nil)
	out, _, ok := r.JSON([]byte(`{"country":"Labland","fullName":"Lab Shopper","mobileNum":5550104242,"zipCode":"10115","streetAddress":"1 Example Street","city":"Labtown","name":"Apple Juice (1000ml)"}`))
	if !ok {
		t.Fatal("JSON rejected")
	}
	for _, s := range []string{"Lab Shopper", "5550104242", "10115", "Example Street"} {
		if strings.Contains(out, s) {
			t.Errorf("personal data %q survived: %s", s, out)
		}
	}
	if !strings.Contains(out, "Apple Juice") {
		t.Errorf("product name redacted: %s", out)
	}
}

func TestStaticAssetsAndValidators(t *testing.T) {
	r := NewRedactor(nil, nil)
	h := http.Header{}
	h.Set("ETag", `W/"5b2-Xh3kQ9vLmP2aR7tYbN4cW8eD1fG0"`)
	if got := r.Headers(h).Get("ETag"); got != h.Get("ETag") {
		t.Errorf("ETag changed: %q", got)
	}
	js := `var a="Q2hhbmdlTWVQbGVhc2VUaGlzSXNBU2VjcmV0S2V5MTIz";var k="` + testAWS + `";`
	out, _ := r.Body("application/javascript; charset=UTF-8", []byte(js))
	if !strings.Contains(out, "Q2hhbmdlTWVQbGVhc2VUaGlzSXNBU2VjcmV0S2V5MTIz") {
		t.Errorf("generic token in JS redacted: %q", out)
	}
	if strings.Contains(out, testAWS) {
		t.Errorf("known key format in JS must still be redacted: %q", out)
	}
	css, _ := r.Body("text/css", []byte(`.x{background:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk)}`))
	if strings.Contains(css, "REDACTED") {
		t.Errorf("CSS data URI redacted: %q", css)
	}
}

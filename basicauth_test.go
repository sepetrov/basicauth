package basicauth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type headers map[string]string
type users map[string]string
type provider struct {
	u map[string]string
}

func (p provider) Find(u []byte) (Credentials, error) {
	if p, ok := p.u[string(u)]; ok {
		return Credentials{User: u, Password: []byte(p)}, nil
	}
	return Credentials{}, fmt.Errorf("Can not find user %s", u)
}

const body = "Hello!"

var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, body)
}
var tests = [...]struct {
	users users
	req   headers
	code  int
	res   headers
	body  string
}{
	{
		users: users{},
		req:   headers{},
		code:  http.StatusUnauthorized,
		res:   headers{"WWW-Authenticate": `Basic realm="` + realm + `"`},
		body:  http.StatusText(http.StatusUnauthorized),
	},
	{
		users: users{},
		req:   headers{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))},
		code:  http.StatusUnauthorized,
		res:   headers{"WWW-Authenticate": `Basic realm="` + realm + `"`},
		body:  http.StatusText(http.StatusUnauthorized),
	},
	{
		users: users{"foo": "bar"},
		req:   headers{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))},
		code:  http.StatusUnauthorized,
		res:   headers{"WWW-Authenticate": `Basic realm="` + realm + `"`},
		body:  http.StatusText(http.StatusUnauthorized),
	},
	{
		users: users{"foo": "bar", "user": "password"},
		req:   headers{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password"))},
		code:  http.StatusOK,
		res:   headers{"WWW-Authenticate": ""},
		body:  body,
	},
}

func TestProtect(t *testing.T) {
	for i, test := range tests {
		p := provider{test.users}
		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", "", nil)
		if err != nil {
			t.Fatalf("%v", err)
		}
		for k, v := range test.req {
			r.Header.Add(k, v)
		}
		http.HandlerFunc(Protect(h, p)).ServeHTTP(w, r)
		if test.code != w.Code {
			t.Errorf("#%d got code %d, want %d ", i, w.Code, test.code)
		}
		for k, v := range test.res {
			if v != w.Header().Get(k) {
				t.Errorf("#%d got header \"%s: %s\", want \"%s: %s\"", i, k, v, k, w.Header().Get(k))
			}
		}
		if test.body != strings.TrimSpace(w.Body.String()) {
			t.Errorf("#%d got body \"%s\", want \"%s\"", i, strings.TrimSpace(w.Body.String()), test.body)
		}
	}
}

func TestBasicAuthProtect(t *testing.T) {
	for i, test := range tests {
		auth := New(provider{test.users})
		w := httptest.NewRecorder()
		r, err := http.NewRequest("GET", "", nil)
		if err != nil {
			t.Fatalf("%v", err)
		}
		for k, v := range test.req {
			r.Header.Add(k, v)
		}
		http.HandlerFunc(auth.Protect(h)).ServeHTTP(w, r)
		if test.code != w.Code {
			t.Errorf("#%d got code %d, want %d ", i, w.Code, test.code)
		}
		for k, v := range test.res {
			if v != w.Header().Get(k) {
				t.Errorf("#%d got header \"%s: %s\", want \"%s: %s\"", i, k, v, k, w.Header().Get(k))
			}
		}
		if test.body != strings.TrimSpace(w.Body.String()) {
			t.Errorf("#%d got body \"%s\", want \"%s\"", i, strings.TrimSpace(w.Body.String()), test.body)
		}
	}
}

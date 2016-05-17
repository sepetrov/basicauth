// Package basicauth is a simple HTTP Basic authentication wrapper.
package basicauth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
)

// Credentials is a structure of user credentials.
type Credentials struct {
	User     []byte
	Password []byte
}

// Provider provides user credentials for the HTTP Basic authentication wrapper.
type Provider interface {
	// Find returns the credentials of user u. It returns an error if user is not found
	// or the user must not be authorised.
	Find(u []byte) (Credentials, error)
}

// BasicAuth is a HTTP Basic authentication wrapper.
type BasicAuth struct {
	p Provider
}

// New creates new HTTP Basic authentication wrapper, which uses the provider p
// and returns a reference to it.
func New(p Provider) *BasicAuth {
	return &BasicAuth{p}
}

// Protect wraps the handler h and returns a handler, which requires valid user
// credentials, using HTTP Basic authentication.
func (a BasicAuth) Protect(h http.HandlerFunc) http.HandlerFunc {
	return Protect(h, a.p)
}

const realm = "Restricted"

// Protect wraps the handler h and returns a handler, which requires valid user
// credentials, using HTTP Basic authentication.
func Protect(h http.HandlerFunc, p Provider) http.HandlerFunc {
	fail := func(w http.ResponseWriter) {
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		const prefix string = "Basic "

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) {
			fail(w)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
		if err != nil {
			fail(w)
			return
		}

		pair := bytes.SplitN(payload, []byte(":"), 2)
		if len(pair) != 2 {
			fail(w)
			return
		}
		user, password := pair[0], pair[1]

		if c, err := p.Find(user); err != nil || !bytes.Equal(password, c.Password) {
			fail(w)
			return
		}

		h(w, r)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bmizerany/assert"
)

func TestHtpasswdProxy(t *testing.T) {
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		count++
		user, pass, ok := req.BasicAuth()
		if !ok || user != "testuser" || pass != "asdf" {
			res.WriteHeader(http.StatusUnauthorized)
			return
		}
		res.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	h, err := NewHtpasswdProxy(server.URL)
	assert.Equal(t, err, nil)

	valid := h.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)

	valid = h.Validate("notfound", "asdf")
	assert.Equal(t, valid, false)

	valid = h.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)

	if count != 2 {
		t.Fatal("consecutive auth should be cached:", count)
	}
}

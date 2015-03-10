package main

import (
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// lookup passwords using external basic auth http server

type HtpasswdProxy struct {
	url   string
	cache struct {
		m map[string]time.Time
		sync.Mutex
	}
}

func NewHtpasswdProxy(urlStr string) (*HtpasswdProxy, error) {
	_, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	h := &HtpasswdProxy{url: urlStr}

	return h, nil
}

func (h *HtpasswdProxy) Validate(user string, password string) bool {
	if h.cachedValidate(user, password) {
		return true
	}
	req, _ := http.NewRequest("GET", h.url, nil)
	req.SetBasicAuth(user, password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Invalid htpasswd proxy response for %s. user:%s error:%v", h.url, user, err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		h.putValidateCache(user, password)
		return true
	}
	return false
}

func (h *HtpasswdProxy) cachedValidate(user string, password string) bool {
	h.cache.Lock()
	if h.cache.m == nil || len(h.cache.m) > 100 {
		h.cache.m = map[string]time.Time{}
	}
	t := h.cache.m[user+":"+password]
	h.cache.Unlock()
	return t.Add(time.Minute).After(time.Now())
}

func (h *HtpasswdProxy) putValidateCache(user string, password string) {
	h.cache.Lock()
	h.cache.m[user+":"+password] = time.Now()
	h.cache.Unlock()
}

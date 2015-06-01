package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bitly/oauth2_proxy/providers"
)

const robotsPath = "/robots.txt"
const pingPath = "/ping"
const signInPath = "/oauth2/sign_in"
const oauthStartPath = "/oauth2/start"
const oauthCallbackPath = "/oauth2/callback"

type OauthProxy struct {
	CookieSeed     string
	CookieKey      string
	CookieDomain   string
	CookieSecure   bool
	CookieHttpOnly bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	Validator      func(string) bool

	redirectUrl         *url.URL // the url to receive requests at
	provider            providers.Provider
	oauthLoginUrl       *url.URL // to redirect the user to
	oauthValidateUrl    *url.URL // to validate the access token
	oauthScope          string
	clientID            string
	clientSecret        string
	SignInMessage       string
	HtpasswdValidator   func(user string, password string) bool
	DisplayHtpasswdForm bool
	serveMux            http.Handler
	PassBasicAuth       bool
	PassAccessToken     bool
	AesCipher           cipher.Block
	skipAuthRegex       []string
	compiledRegex       []*regexp.Regexp
	templates           *template.Template
}

type UpstreamProxy struct {
	upstream string
	handler  http.Handler
}

func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("GAP-Upstream-Address", u.upstream)
	u.handler.ServeHTTP(w, r)
}

func NewReverseProxy(target *url.URL) (proxy *httputil.ReverseProxy) {
	return httputil.NewSingleHostReverseProxy(target)
}
func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.Host = target.Host
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}
func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}

func NewOauthProxy(opts *Options, validator func(string) bool) *OauthProxy {
	serveMux := http.NewServeMux()
	for _, u := range opts.proxyUrls {
		path := u.Path
		u.Path = ""
		log.Printf("mapping path %q => upstream %q", path, u)
		proxy := NewReverseProxy(u)
		if !opts.PassHostHeader {
			setProxyUpstreamHostHeader(proxy, u)
		} else {
			setProxyDirector(proxy)
		}
		serveMux.Handle(path, &UpstreamProxy{u.Host, proxy})
	}
	for _, u := range opts.CompiledRegex {
		log.Printf("compiled skip-auth-regex => %q", u)
	}

	redirectUrl := opts.redirectUrl
	redirectUrl.Path = oauthCallbackPath

	log.Printf("OauthProxy configured for %s", opts.ClientID)
	domain := opts.CookieDomain
	if domain == "" {
		domain = "<default>"
	}
	if !opts.CookieHttpsOnly {
		log.Printf("Warning: cookie-https-only setting is deprecated and will be removed in a future version. use cookie-secure")
		opts.CookieSecure = opts.CookieHttpsOnly
	}

	log.Printf("Cookie settings: secure (https):%v httponly:%v expiry:%s domain:%s", opts.CookieSecure, opts.CookieHttpOnly, opts.CookieExpire, domain)

	var aes_cipher cipher.Block
	if opts.PassAccessToken || (opts.CookieRefresh != time.Duration(0)) {
		var err error
		aes_cipher, err = aes.NewCipher([]byte(opts.CookieSecret))
		if err != nil {
			log.Fatal("error creating AES cipher with "+
				"cookie-secret ", opts.CookieSecret, ": ", err)
		}
	}

	return &OauthProxy{
		CookieKey:      "_oauthproxy",
		CookieSeed:     opts.CookieSecret,
		CookieDomain:   opts.CookieDomain,
		CookieSecure:   opts.CookieSecure,
		CookieHttpOnly: opts.CookieHttpOnly,
		CookieExpire:   opts.CookieExpire,
		CookieRefresh:  opts.CookieRefresh,
		Validator:      validator,

		clientID:         opts.ClientID,
		clientSecret:     opts.ClientSecret,
		oauthScope:       opts.provider.Data().Scope,
		provider:         opts.provider,
		oauthLoginUrl:    opts.provider.Data().LoginUrl,
		oauthValidateUrl: opts.provider.Data().ValidateUrl,
		serveMux:         serveMux,
		redirectUrl:      redirectUrl,
		skipAuthRegex:    opts.SkipAuthRegex,
		compiledRegex:    opts.CompiledRegex,
		PassBasicAuth:    opts.PassBasicAuth,
		PassAccessToken:  opts.PassAccessToken,
		AesCipher:        aes_cipher,
		templates:        loadTemplates(opts.CustomTemplatesDir),
	}
}

func (p *OauthProxy) GetRedirectUrl(host string) string {
	// default to the request Host if not set
	if p.redirectUrl.Host != "" {
		return p.redirectUrl.String()
	}
	var u url.URL
	u = *p.redirectUrl
	if u.Scheme == "" {
		if p.CookieSecure {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	u.Host = host
	return u.String()
}

func (p *OauthProxy) GetLoginURL(host, redirect string) string {
	params := url.Values{}
	params.Add("redirect_uri", p.GetRedirectUrl(host))
	params.Add("approval_prompt", "force")
	params.Add("scope", p.oauthScope)
	params.Add("client_id", p.clientID)
	params.Add("response_type", "code")
	if strings.HasPrefix(redirect, "/") {
		params.Add("state", redirect)
	}
	return fmt.Sprintf("%s?%s", p.oauthLoginUrl, params.Encode())
}

func (p *OauthProxy) displayCustomLoginForm() bool {
	return p.HtpasswdValidator != nil && p.DisplayHtpasswdForm
}

func (p *OauthProxy) redeemCode(host, code string) (string, string, error) {
	if code == "" {
		return "", "", errors.New("missing code")
	}
	redirectUri := p.GetRedirectUrl(host)
	body, access_token, err := p.provider.Redeem(redirectUri, code)
	if err != nil {
		return "", "", err
	}

	email, err := p.provider.GetEmailAddress(body, access_token)
	if err != nil {
		return "", "", err
	}

	return access_token, email, nil
}

func (p *OauthProxy) MakeCookie(req *http.Request, value string, expiration time.Duration) *http.Cookie {
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if p.CookieDomain != "" {
		if !strings.HasSuffix(domain, p.CookieDomain) {
			log.Printf("Warning: request host is %q but using configured cookie domain of %q", domain, p.CookieDomain)
		}
		domain = p.CookieDomain
	}

	if value != "" {
		value = signedCookieValue(p.CookieSeed, p.CookieKey, value)
	}

	return &http.Cookie{
		Name:     p.CookieKey,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: p.CookieHttpOnly,
		Secure:   p.CookieSecure,
		Expires:  time.Now().Add(expiration),
	}
}

func (p *OauthProxy) ClearCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, p.MakeCookie(req, "", time.Duration(1)*time.Hour*-1))
}

func (p *OauthProxy) SetCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, p.MakeCookie(req, val, p.CookieExpire))
}

func (p *OauthProxy) ProcessCookie(rw http.ResponseWriter, req *http.Request) (email, user, access_token string, ok bool) {
	var value string
	var timestamp time.Time
	cookie, err := req.Cookie(p.CookieKey)
	if err == nil {
		value, timestamp, ok = validateCookie(cookie, p.CookieSeed)
		if ok {
			email, user, access_token, err = parseCookieValue(
				value, p.AesCipher)
		}
	}
	if err != nil {
		log.Printf(err.Error())
		ok = false
	} else if p.CookieRefresh != time.Duration(0) {
		expires := timestamp.Add(p.CookieExpire)
		refresh_threshold := time.Now().Add(p.CookieRefresh)
		if refresh_threshold.Unix() > expires.Unix() {
			ok = p.Validator(email) && p.provider.ValidateToken(access_token)
			if ok {
				p.SetCookie(rw, req, value)
			}
		}
	}
	return
}

func (p *OauthProxy) RobotsTxt(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

func (p *OauthProxy) PingPage(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
}

func (p *OauthProxy) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	log.Printf("ErrorPage %d %s %s", code, title, message)
	rw.WriteHeader(code)
	t := struct {
		Title   string
		Message string
	}{
		Title:   fmt.Sprintf("%d %s", code, title),
		Message: message,
	}
	p.templates.ExecuteTemplate(rw, "error.html", t)
}

func (p *OauthProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	p.ClearCookie(rw, req)
	rw.WriteHeader(code)

	redirect_url := req.URL.RequestURI()
	if redirect_url == signInPath {
		redirect_url = "/"
	}

	t := struct {
		ProviderName  string
		SignInMessage string
		CustomLogin   bool
		Redirect      string
		Version       string
	}{
		ProviderName:  p.provider.Data().ProviderName,
		SignInMessage: p.SignInMessage,
		CustomLogin:   p.displayCustomLoginForm(),
		Redirect:      redirect_url,
		Version:       VERSION,
	}
	p.templates.ExecuteTemplate(rw, "sign_in.html", t)
}

func (p *OauthProxy) ManualSignIn(rw http.ResponseWriter, req *http.Request) (string, bool) {
	if req.Method != "POST" || p.HtpasswdValidator == nil {
		return "", false
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.HtpasswdValidator(user, passwd) {
		log.Printf("authenticated %q via manual sign in", user)
		return user, true
	}
	return "", false
}

func (p *OauthProxy) GetRedirect(req *http.Request) (string, error) {
	err := req.ParseForm()

	if err != nil {
		return "", err
	}

	redirect := req.FormValue("rd")

	if redirect == "" {
		redirect = "/"
	}

	return redirect, err
}

func (p *OauthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// check if this is a redirect back at the end of oauth
	remoteAddr := req.RemoteAddr
	if req.Header.Get("X-Real-IP") != "" {
		remoteAddr += fmt.Sprintf(" (%q)", req.Header.Get("X-Real-IP"))
	}

	var ok bool
	var user string
	var email string
	var access_token string

	if req.URL.Path == robotsPath {
		p.RobotsTxt(rw)
		return
	}

	if req.URL.Path == pingPath {
		p.PingPage(rw)
		return
	}

	for _, u := range p.compiledRegex {
		match := u.MatchString(req.URL.Path)
		if match {
			p.serveMux.ServeHTTP(rw, req)
			return
		}

	}

	if req.URL.Path == signInPath {
		redirect, err := p.GetRedirect(req)
		if err != nil {
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}

		user, ok = p.ManualSignIn(rw, req)
		if ok {
			p.SetCookie(rw, req, user)
			http.Redirect(rw, req, redirect, 302)
		} else {
			p.SignInPage(rw, req, 200)
		}
		return
	}
	if req.URL.Path == oauthStartPath {
		redirect, err := p.GetRedirect(req)
		if err != nil {
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}
		http.Redirect(rw, req, p.GetLoginURL(req.Host, redirect), 302)
		return
	}
	if req.URL.Path == oauthCallbackPath {
		// finish the oauth cycle
		err := req.ParseForm()
		if err != nil {
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}
		errorString := req.Form.Get("error")
		if errorString != "" {
			p.ErrorPage(rw, 403, "Permission Denied", errorString)
			return
		}

		access_token, email, err = p.redeemCode(req.Host, req.Form.Get("code"))
		if err != nil {
			log.Printf("%s error redeeming code %s", remoteAddr, err)
			p.ErrorPage(rw, 500, "Internal Error", err.Error())
			return
		}

		redirect := req.Form.Get("state")
		if redirect == "" {
			redirect = "/"
		}

		// set cookie, or deny
		if p.Validator(email) {
			log.Printf("%s authenticating %s completed", remoteAddr, email)
			value, err := buildCookieValue(
				email, p.AesCipher, access_token)
			if err != nil {
				log.Printf(err.Error())
			}
			p.SetCookie(rw, req, value)
			http.Redirect(rw, req, redirect, 302)
			return
		} else {
			p.ErrorPage(rw, 403, "Permission Denied", "Invalid Account")
			return
		}
	}

	if !ok {
		email, user, access_token, ok = p.ProcessCookie(rw, req)
	}

	if !ok {
		user, ok = p.CheckBasicAuth(req)
	}

	if !ok {
		p.SignInPage(rw, req, 403)
		return
	}

	// At this point, the user is authenticated. proxy normally
	if p.PassBasicAuth {
		req.SetBasicAuth(user, "")
		req.Header["X-Forwarded-User"] = []string{user}
		req.Header["X-Forwarded-Email"] = []string{email}
	}
	if p.PassAccessToken {
		req.Header["X-Forwarded-Access-Token"] = []string{access_token}
	}
	if email == "" {
		rw.Header().Set("GAP-Auth", user)
	} else {
		rw.Header().Set("GAP-Auth", email)
	}

	p.serveMux.ServeHTTP(rw, req)
}

func (p *OauthProxy) CheckBasicAuth(req *http.Request) (string, bool) {
	if p.HtpasswdValidator == nil {
		return "", false
	}
	s := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", false
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return "", false
	}
	if p.HtpasswdValidator(pair[0], pair[1]) {
		log.Printf("authenticated %q via basic auth", pair[0])
		return pair[0], true
	}
	return "", false
}

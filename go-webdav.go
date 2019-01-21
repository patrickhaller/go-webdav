package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/patrickhaller/confix"
	"github.com/patrickhaller/go-ldap-client"
	"github.com/patrickhaller/slog"
	"github.com/patrickhaller/toml"
	"golang.org/x/net/webdav"
)

// configuration is via TOML
var cfg struct {
	Port                  string
	Root                  string   // serve webdav from here
	Roots                 []string // tho try first to serve webdav from here
	Prefix                string   // prefix to strip from URL path
	AuthFailWindow        int      //seconds
	AuthFailMaxCount      int
	AuthFailLogPer        int // log too many auth fails every Nth fail
	AuthClientsWindow     int // how long to keep record of clients
	LogFile               string
	AuditFile             string
	Debug                 bool
	DecapitalizeUserNames bool
	TrimUserNames         bool
	LdapBase              string
	LdapHost              string
	LdapPort              int
	LdapBindDN            string
	LdapBindPassword      string
	LdapUserFilter        string
	LdapGroupFilter       string
	LdapAttributes        []string
	LdapSkipTLS           bool
	LdapUseSSL            bool
	LdapServerName        string
}

var webdavLockSystem = webdav.NewMemLS()

type client struct {
	id   string
	time time.Time
}

type last struct {
	time time.Time
}

var lastFails = make(map[string][]last)
var currentClients = make(map[string][]client)
var okClients = make(map[string][]client)

func readConfig() {
	configfile := flag.String("cf", "/etc/go-webdavd.toml", "TOML config file")
	flag.Parse()
	if _, err := os.Stat(*configfile); err != nil {
		slog.P("Config file `%s' is inaccessible: %v", *configfile, err)
	}

	if _, err := toml.DecodeFile(*configfile, &cfg); err != nil {
		slog.P("Config file `%s' failed to parse: %v", *configfile, err)
	}
}

func logRequest(username string) func(*http.Request, error) {
	return func(r *http.Request, err error) {
		base := fmt.Sprintf("%s %s %s length:%d %s via %s %s", username, r.Method, r.URL,
			r.ContentLength, r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.UserAgent())
		if err == nil {
			slog.A("REQUEST %s", base)
			return
		}
		slog.A("ERROR %s %v", base, err)
	}
}

func filesystem(username string) webdav.FileSystem {
	if len(cfg.Roots) != 0 {
		for i := range cfg.Roots {
			dir := fmt.Sprintf(cfg.Roots[i], username)
			if _, err := os.Stat(dir); err == nil {
				slog.D("using local filesystem at %s\n", dir)
				return webdav.Dir(dir)
			}
		}
	}

	dir := fmt.Sprintf(cfg.Root, username)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		slog.P("FS for user `%s' at `%s' does not exist: %v", username, dir, err)
		return nil
	}
	slog.D("using local filesystem at %s\n", dir)
	return webdav.Dir(dir)
}

func hasFsPerms(username string) bool {
	u, err := user.Lookup(username)
	if err != nil {
		slog.P("failed uid lookup for user `%s': %v", username, err)
		return false
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		slog.P("failed integer conversion for user `%s' uid `%s': %v", username, uid, err)
		return false
	}
	slog.D("user %s has uid %d", username, uid)

	if err := syscall.Setfsuid(uid); err != nil {
		slog.P("setfsuid failed for user '%s':  %v", username, err)
		return false
	}

	if err := syscall.Setfsgid(uid); err != nil {
		slog.P("setfsgid failed for user '%s': %v", username, err)
		return false
	}

	return true
}

func isLdap(username, pw string) bool {
	slog.D("user %s ldap start", username)
	c := ldap.LDAPClient{}
	if err := confix.Confix("Ldap", &cfg, &c); err != nil {
		slog.P("confix failed: `%v'", err)
		return false
	}
	defer c.Close()

	ok, _, err := c.Authenticate(username, pw)
	if err != nil {
		slog.P("ldap error authenticating user `%s': %+v", username, err)
		return false
	}
	if ok {
		slog.D("ldap auth success for user: `%s'", username)
		return true
	}

	slog.P("ldap auth failed for user `%s'", username)
	return false
}

func basicAuth(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		slog.D("no basic auth?")
		return "", "", false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		slog.D("basic auth b64 bad encoding: %v", err)
		return "", "", false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		slog.D("basic auth malformed? needs username:passwd")
		return "", "", false
	}
	return pair[0], pair[1], true
}

func remoteID(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "_" + r.Header.Get("X-Forwarded-For")
	}
	return host + "_" + r.Header.Get("X-Forwarded-For")
}

func isClient(clients []client, r *http.Request) bool {
	rmt := remoteID(r)
	for i := range clients {
		if clients[i].id == rmt {
			return true
		}
	}
	return false
}

func rmOldClients(clients []client, windowSeconds int) []client {
	var live []client
	window := time.Second * time.Duration(windowSeconds)
	now := time.Now()

	for i := range clients {
		if clients[i].time.Add(window).After(now) {
			live = append(live, clients[i])
		}
	}
	return live
}

func rmOldLasts(lasts []last, windowSeconds int) []last {
	var live []last
	window := time.Second * time.Duration(windowSeconds)
	now := time.Now()

	for i := range lasts {
		if lasts[i].time.Add(window).After(now) {
			live = append(live, lasts[i])
		}
	}
	return live
}

func hasTooManyPasswdAttempts(username string, r *http.Request) bool {
	ok := isClient(okClients[username], r)
	okClients[username] = rmOldClients(okClients[username], cfg.AuthClientsWindow)
	if ok {
		okClients[username] = append(okClients[username], client{remoteID(r), time.Now()})
		return false
	}

	clients := rmOldClients(currentClients[username], cfg.AuthClientsWindow)
	if !isClient(clients, r) {
		// allow one guess to prevent DoS
		currentClients[username] = append(currentClients[username], client{remoteID(r), time.Now()})
		return false
	}

	lasts := rmOldLasts(lastFails[username], cfg.AuthFailWindow)
	if len(lasts) >= cfg.AuthFailMaxCount {
		if len(lasts)%cfg.AuthFailLogPer == 1 {
			slog.P("auth too many fails for `%s' with %d attempts", username, len(lasts))
		}
		return true
	}
	lastFails[username] = append(lasts, last{time.Now()})
	return false
}

func isAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	u, p, ok := basicAuth(w, r)
	if ok == false {
		w.Header().Set(`X-Auth-Error`, fmt.Sprintf(`Mal-formed basic auth`))
		return "", fmt.Errorf("Mal-formed basic auth")
	}

	if u == "" || p == "" {
		w.Header().Set(`X-Auth-Error`, fmt.Sprintf(`Mal-formed userid or password`))
		return "", fmt.Errorf("Mal-formed userid or password")
	}

	if cfg.TrimUserNames == true {
		u = strings.TrimSpace(u)
	}

	if cfg.DecapitalizeUserNames == true {
		u = strings.ToLower(u)
	}

	if hasTooManyPasswdAttempts(u, r) == true {
		w.Header().Set(`X-Auth-Error`,
			fmt.Sprintf(`Too many attempts, retry in %d seconds`, cfg.AuthFailWindow))
		return "", fmt.Errorf("Too many authentication attempts, try back in %d seconds", cfg.AuthFailWindow)
	}

	if isLdap(u, p) == true {
		slog.D("user `%s' logged in from %s via %s", u, r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
		okClients[u] = append(okClients[u], client{remoteID(r), time.Now()})
		return u, nil
	}

	slog.P("auth fail for `%s' from %s via %s", u, r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
	lastFails[u] = append(lastFails[u], last{time.Now()})
	return "", fmt.Errorf("Authentication failed for `%s'", u)
}

/* goroutines mux M:N to pthreads, so lock to one pthread to keep
   the setfsuid perms only to this goroutine
   https://github.com/golang/go/issues/1435
      describes the issue
   https://github.com/golang/go/issues/20395
      in go1.10 runtime.ThreadExit() should arrive
*/
func router(w http.ResponseWriter, r *http.Request) {
	username, err := isAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}

	runtime.LockOSThread()

	if hasFsPerms(username) == false {
		http.Error(w, "FS error", 403)
		return
	}

	h := webdav.Handler{
		Prefix:     cfg.Prefix,
		LockSystem: webdavLockSystem,
		FileSystem: filesystem(username),
		Logger:     logRequest(username),
	}

	h.ServeHTTP(w, r)
}

func main() {
	readConfig()
	slog.Init(slog.Config{
		File:      cfg.LogFile,
		Debug:     cfg.Debug,
		AuditFile: cfg.AuditFile,
		Prefix:    "WBDV",
	})
	slog.D("go-webdav starting up on %s...", cfg.Port)

	sigh := make(chan os.Signal, 1)
	signal.Notify(sigh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigh
		slog.P("go-webdav received `%v', exiting...", sig)
		os.Exit(1)
	}()

	http.HandleFunc("/", router)
	if err := http.ListenAndServe(cfg.Port, nil); err != nil {
		slog.P("Cannot bind `%s': %v", cfg.Port, err)
	}
}

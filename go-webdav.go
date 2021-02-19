package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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
	UIDAttribute          string   // LDAP attribute that has the users UID
	AuthFailWindow        int      // seconds
	AuthFailMaxCount      int
	AuthFailLogPer        int // log too many auth fails every Nth fail
	AuthClientsWindow     int // how long to keep record of clients
	AuthDenialIsDisabled  bool
	LogFile               string
	AuditFile             string
	Debug                 bool
	DecapitalizeUserNames bool
	TrimUserNames         bool
	Ldap                  ldap.LDAPClient
}

var webdavLockSystem = webdav.NewMemLS()

type davUser struct {
	name string
	uid  int
}

type client struct {
	id   string
	time time.Time
}

/* DoS + brute force prevention =
   keep track of login fails per user,
   and which clients have auth'd ok,
   and every client regardless */
var lastFails = make(map[string][]client)
var okClients = make(map[string][]client)
var allClients = make(map[string][]client)

func readConfig() {
	configfile := flag.String("cf", "/etc/go-webdavd.toml", "TOML config file")
	flag.Parse()
	if _, err := os.Stat(*configfile); err != nil {
		slog.P("Config file `%s' is inaccessible: %v", *configfile, err)
	}

	if _, err := toml.DecodeFile(*configfile, &cfg); err != nil {
		slog.P("Config file `%s' failed to parse: %v", *configfile, err)
	}

	if cfg.Ldap.Host == "" {
		slog.F("Config file `%v' has no ldap host", *configfile)
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

func hasFsPerms(davuser *davUser) (err error) {

	slog.D("user %s has uid %d", davuser.name, davuser.uid)

	if err := syscall.Setfsuid(davuser.uid); err != nil {
		return fmt.Errorf("setfsuid failed for user '%s':  %v", davuser.name, err)
	}

	if err := syscall.Setfsgid(davuser.uid); err != nil {
		return fmt.Errorf("setfsgid failed for user '%s': %v", davuser.name, err)
	}

	return nil
}

func isLdap(u, p string, davuser *davUser) (err error) {
	slog.D("user %s ldap start", u)
	c := cfg.Ldap
	defer c.Close()

	ok, ldapuser, err := c.Authenticate(u, p)
	if err != nil {
		return fmt.Errorf("ldap error authenticating user `%s': %+v", u, err)
	}
	if !ok {
		return fmt.Errorf("ldap auth failed for user `%v'", u)
	}
	slog.D("ldap auth success for user: `%s'", u)
	davuser.name = u
	davuser.uid, err = strconv.Atoi(ldapuser[cfg.UIDAttribute])
	if err != nil {
		return fmt.Errorf("failed integer conversion for user `%s' uid `%s': %v",
			u, ldapuser[cfg.UIDAttribute], err)
	}
	return nil
}

func basicAuth(w http.ResponseWriter, r *http.Request) (user string, passwd string, err error) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return "", "", fmt.Errorf("no basic auth?")
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", "", fmt.Errorf("basicAuth decode failed: %v", err)
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return "", "", fmt.Errorf("basic auth malformed? needs username:passwd")
	}

	user, passwd = pair[0], pair[1]
	if user == "" || passwd == "" {
		return "", "", fmt.Errorf("basic auth malformed? empty username:passwd")
	}

	matched, err := regexp.MatchString(`^[a-z][a-z_\.-]+$`, user)
	if err != nil {
		return "", "", fmt.Errorf("bad user match: %v", err)
	}
	if !matched {
		return "", "", fmt.Errorf("bad user: `%v'", user)
	}

	matched, err = regexp.MatchString(`^[^'"]+$`, passwd)
	if err != nil {
		return "", "", fmt.Errorf("bad passwd match: %v", err)
	}
	if !matched {
		return "", "", fmt.Errorf("bad passwd: `%v'", passwd)
	}

	return user, passwd, nil
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

func hasTooManyPasswordAttempts(username string, r *http.Request) bool {
	okClients[username] = rmOldClients(okClients[username], cfg.AuthClientsWindow)

	if cfg.AuthDenialIsDisabled {
		return false
	}

	clients := rmOldClients(allClients[username], cfg.AuthClientsWindow)
	if !isClient(clients, r) {
		// allow one guess to prevent DoS
		allClients[username] = append(allClients[username], client{remoteID(r), time.Now()})
		slog.D("user `%s' with new client id first auth `%s'", username, remoteID(r))
		return false
	}

	lasts := rmOldClients(lastFails[username], cfg.AuthFailWindow)
	if len(lasts) >= cfg.AuthFailMaxCount {
		slog.D("user `%s' too many auth fails %d", username, len(lasts))
		if len(lasts)%cfg.AuthFailLogPer == 1 {
			slog.P("auth too many fails for `%s' with %d attempts", username, len(lasts))
		}
		return true
	}
	lastFails[username] = append(lasts, client{time: time.Now()})
	slog.D("user `%s' does not have too many auth fails, count %d", username, len(lasts))
	return false
}

func isAuth(w http.ResponseWriter, r *http.Request, davuser *davUser) (err error) {
	u, p, err := basicAuth(w, r)
	if err != nil {
		return fmt.Errorf("bad auth: %v", err)
	}

	if u == "" || p == "" {
		return fmt.Errorf("Mal-formed userid or password: `%v' `%v'", u, p)
	}

	if cfg.TrimUserNames == true {
		u = strings.TrimSpace(u)
	}

	if cfg.DecapitalizeUserNames == true {
		u = strings.ToLower(u)
	}

	if hasTooManyPasswordAttempts(u, r) == true {
		return fmt.Errorf("Too many authentication attempts for %v", u)
	}

	if err = isLdap(u, p, davuser); err != nil {
		lastFails[u] = append(lastFails[u], client{time: time.Now()})
		return fmt.Errorf("Authentication failed for `%s', %v", u, err)
	}

	okClients[u] = append(okClients[u], client{remoteID(r), time.Now()})
	return nil
}

/* goroutines mux M:N to pthreads, so lock to one pthread to keep
   the setfsuid perms only to this goroutine
   https://github.com/golang/go/issues/1435
      describes the issue
   https://github.com/golang/go/issues/20395
      in go1.10 runtime.ThreadExit() should arrive
*/
func router(w http.ResponseWriter, r *http.Request) {
	var user davUser
	if err := isAuth(w, r, &user); err != nil {
		slog.P("auth fail from %s: %v", remoteID(r), err)
		http.Error(w, "Authentication Failed", 401)
		return
	}
	slog.D("user `%s' logged in from %s via %s",
		user.name, r.RemoteAddr, r.Header.Get("X-Forwarded-For"))

	runtime.LockOSThread()

	if err := hasFsPerms(&user); err != nil {
		slog.P("failing due to FS: %v", err)
		http.Error(w, "FS error", 403)
		return
	}

	h := webdav.Handler{
		Prefix:     cfg.Prefix,
		LockSystem: webdavLockSystem,
		FileSystem: filesystem(user.name),
		Logger:     logRequest(user.name),
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
	slog.P("go-webdav starting up on %s...", cfg.Port)

	sigh := make(chan os.Signal, 1)
	signal.Notify(sigh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigh
		slog.P("go-webdav received `%v', exiting...", sig)
		os.Exit(1)
	}()

	syscall.Umask(0002)

	http.HandleFunc("/", router)
	if err := http.ListenAndServe(cfg.Port, nil); err != nil {
		slog.P("Cannot bind `%s': %v", cfg.Port, err)
	}
}

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jtblin/go-ldap-client"
	"github.com/patrickhaller/slog"
	"golang.org/x/net/webdav"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// configuration is via TOML
var cfg struct {
	Port             string
	Root             string // serve webdav from here
	Prefix           string // prefix to strip from URL path
	LogFile          string
	AuditFile        string
	Debug            bool
	LdapBase         string
	LdapHost         string
	LdapPort         int
	LdapBindDN       string
	LdapBindPassword string
	LdapUserFilter   string
	LdapGroupFilter  string
	LdapAttributes   []string
	LdapSkipTLS      bool
	LdapUseSSL       bool
	LdapServerName   string
}

var webdavLockSystem = webdav.NewMemLS()

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
		slog.A("REQUEST %s %s %s length:%d %s %s", username, r.Method, r.URL,
			r.ContentLength, r.RemoteAddr, r.UserAgent())
		if err != nil {
			slog.A("ERROR %s %s %s length:%d %s %s %v", username, r.Method, r.URL,
				r.ContentLength, r.RemoteAddr, r.UserAgent(), err)
		}
	}
}

func filesystem(username string) webdav.FileSystem {
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
	client := ldap.LDAPClient{
		Base:       cfg.LdapBase,
		Host:       cfg.LdapHost,
		Port:       cfg.LdapPort,
		UserFilter: cfg.LdapUserFilter,
	}
	if cfg.LdapGroupFilter != "" {
		client.GroupFilter = cfg.LdapGroupFilter
	}
	if cfg.LdapUseSSL != false {
		client.UseSSL = cfg.LdapUseSSL
		client.ServerName = cfg.LdapServerName
	}
	if cfg.LdapSkipTLS != false {
		client.SkipTLS = cfg.LdapSkipTLS
	}
	if cfg.LdapBindDN != "" {
		client.BindDN = cfg.LdapBindDN
	}
	if cfg.LdapBindPassword != "" {
		client.BindPassword = cfg.LdapBindPassword
	}
	if cfg.LdapAttributes != nil {
		client.Attributes = cfg.LdapAttributes
	}
	defer client.Close()

	ok, _, err := client.Authenticate(username, pw)
	if err != nil {
		slog.P("ldap error authenticating user `%s': %+v", username, err)
		return false
	}
	if !ok {
		slog.P("ldap auth failed for user `%s'", username)
		return false
	}
	slog.D("ldap auth success for user: `%s'", username)

	return true
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

func isAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	u, p, ok := basicAuth(w, r)
	if ok == false {
		return "", false
	}

	if isLdap(u, p) == false {
		return "", false
	}

	slog.D("user %s logged in", u)
	return u, true
}

/* goroutines mux M:N to pthreads, so lock to one pthread to keep
   the setfsuid perms only to this goroutine
   https://github.com/golang/go/issues/1435
      describes the issue
   https://github.com/golang/go/issues/20395
      in go1.10 runtime.ThreadExit() should arrive
*/
func router(w http.ResponseWriter, r *http.Request) {
	username, ok := isAuth(w, r)
	if ok == false {
		http.Error(w, "Not authorized", 401)
		return
	}

	runtime.LockOSThread()

	if hasFsPerms(username) == false {
		http.Error(w, "FS error", 500)
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
	slog.D("go-webdav starting up...")

	http.HandleFunc("/", router)
	if err := http.ListenAndServe(cfg.Port, nil); err != nil {
		slog.P("Cannot bind `%s': %v", cfg.Port, err)
	}
}

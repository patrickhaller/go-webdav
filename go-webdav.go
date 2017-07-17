package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jtblin/go-ldap-client"
	"golang.org/x/net/webdav"
	"log"
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
	LogLevel         int // 0 (none) or 1 (errors) or 2 (requests) or 3 (all)
	LdapBase         string
	LdapHost         string
	LdapPort         int
	LdapUseSSL       bool
	LdapBindDN       string
	LdapBindPassword string
	LdapUserFilter   string
	LdapGroupFilter  string
	LdapAttributes   []string
}

var webdavLockSystem = webdav.NewMemLS()

func readConfig() {
	configfile := flag.String("cf", "/etc/go-webdavd.toml", "TOML config file")
	flag.Parse()
	if _, err := os.Stat(*configfile); err != nil {
		log.Printf("Config file `%s' is inaccessible: %v", *configfile, err)
	}

	if _, err := toml.DecodeFile(*configfile, &cfg); err != nil {
		log.Printf("Config file `%s' failed to parse: %v", *configfile, err)
	}
}

func debug(f string, a ...interface{}) {
	if cfg.LogLevel >= 3 {
		log.Printf(f, a...)
	}
}

func logRequest(username string) func(*http.Request, error) {
	switch cfg.LogLevel {
	case 3:
		fallthrough
	case 2:
		return func(r *http.Request, err error) {
			log.Printf("REQUEST %s %s %s length:%d %s %s\n", username, r.Method, r.URL,
				r.ContentLength, r.RemoteAddr, r.UserAgent())
			if err != nil {
				log.Printf("ERROR %s %s %s %v\n", username, r.Method, r.URL, err)
			}
		}
	case 1:
		return func(r *http.Request, err error) {
			if err != nil {
				log.Printf("ERROR %s %s %s %v\n", username, r.Method, r.URL, err)
			}
		}
	default:
		return nil
	}
}

func filesystem(username string) webdav.FileSystem {
	dir := fmt.Sprintf(cfg.Root, username)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Printf("FS for user `%s' at `%s' does not exist: %v", username, dir, err)
		return nil
	}
	debug("using local filesystem at %s\n", dir)
	return webdav.Dir(dir)
}

func hasFsPerms(username string) bool {
	u, err := user.Lookup(username)
	if err != nil {
		return false
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return false
	}
	debug("user %s has uid %d", username, uid)

	if err := syscall.Setfsuid(uid); err != nil {
		log.Printf("setfsuid failed for user '%s':  %v", username, err)
		return false
	}

	if err := syscall.Setfsgid(uid); err != nil {
		log.Printf("setfsgid failed for user '%s': %v", username, err)
		return false
	}

	return true
}

func isLdap(username, pw string) bool {
	debug("user %s ldap start", username)
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
		log.Printf("ldap error authenticating user `%s': %+v", username, err)
		return false
	}
	if !ok {
		log.Printf("ldap auth failed for user `%s'", username)
		return false
	}
	debug("ldap auth success for user: `%s'", username)

	return true
}

func basicAuth(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return "", "", false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return "", "", false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
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

	debug("user %s logged in", u)
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
	log.Printf("go-webdav starting up...")

	logFile, err := os.OpenFile(cfg.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("Open logfile `%s' failed: %v", cfg.LogFile, err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	http.HandleFunc("/", router)
	if err := http.ListenAndServe(cfg.Port, nil); err != nil {
		log.Fatalf("Cannot bind `%s': %v", cfg.Port, err)
	}
}

package main

import (
	"encoding/base64"
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

const (
	logLevelNone = "none"
	logLevelAll  = "all"
	envPrefix    = "PREFIX"
	envLoglevel  = "LOGLEVEL"
	pathRoot     = "./"
	pathLog      = "/dev/stderr"
)

func logger() func(*http.Request, error) {
	switch os.Getenv(envLoglevel) {
	case logLevelNone:
		return nil
	case logLevelAll:
		return func(r *http.Request, err error) {
			log.Printf("REQUEST %s %s length:%d %s %s\n", r.Method, r.URL,
				r.ContentLength, r.RemoteAddr, r.UserAgent())
		}
	default:
		return func(r *http.Request, err error) {
			if err != nil {
				log.Printf("ERROR %v\n", err)
			}
		}
	}
}

func filesystem() webdav.FileSystem {
	if err := os.Mkdir(pathRoot, os.ModePerm); !os.IsExist(err) {
		log.Fatalf("FATAL %v", err)
	}
	log.Printf("INFO using local filesystem at %s\n", pathRoot)
	return webdav.Dir(pathRoot)
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
	log.Printf("user %s has uid %d", username, uid)

	if err := syscall.Setfsuid(uid); err != nil {
		log.Printf("setfsuid for user '%s':  %v", username, err)
		return false
	}

	if err := syscall.Setfsgid(uid); err != nil {
		log.Printf("setfsgid for user '%s': %v", username, err)
		return false
	}

	return true
}

func isLdap(username, pw string) bool {
	log.Printf("user %s ldap start", username)
	client := &ldap.LDAPClient{
		Base:   "dc=ofs,dc=edu,dc=sg",
		Host:   "ldap.ofs.edu.sg",
		Port:   389,
		UseSSL: false,
		//BindDN:       "uid=readonlysuer,ou=people,dc=ofs,dc=edu,dc=sg",
		//BindPassword: "readonlypassword",
		UserFilter:  "(uid=%s)",
		GroupFilter: "(memberUid=%s)",
		Attributes:  []string{"givenName", "sn", "mail", "uid"},
	}
	// It is the responsibility of the caller to close the connection
	defer client.Close()

	ok, _, err := client.Authenticate(username, pw)
	if err != nil {
		log.Printf("Error authenticating user %s: %+v", username, err)
		return false
	}
	if !ok {
		log.Printf("Authentication failed for user %s", username)
		return false
	}
	log.Printf("ldap auth success for user: %+v", username)

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

/* goroutines mux M:N to pthreads, so lock to one pthread to keep
   the setfsuid perms only to this goroutine
   https://github.com/golang/go/issues/1435
   https://github.com/golang/go/issues/20395
*/
func isAuth(w http.ResponseWriter, r *http.Request) bool {
	u, p, ok := basicAuth(w, r)
	if ok == false {
		return false
	}

	if isLdap(u, p) == false {
		return false
	}

	runtime.LockOSThread()

	if hasFsPerms(u) == false {
		return false
	}

	log.Printf("user %s logged in", u)
	return true
}

func router(h *webdav.Handler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if isAuth(w, r) == true {
			h.ServeHTTP(w, r)
		} else {
			http.Error(w, "Not authorized", 401)
		}
	}
}

func main() {
	logFile, err := os.OpenFile(pathLog, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("FATAL %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Printf("stripping url prefix = '%s'\n", os.Getenv(envPrefix))
	h := &webdav.Handler{
		Prefix:     os.Getenv(envPrefix),
		FileSystem: filesystem(),
		LockSystem: webdav.NewMemLS(),
		Logger:     logger(),
	}

	http.HandleFunc("/", router(h))
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		log.Fatalf("Cannot bind: %v", err)
	}
}

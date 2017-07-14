package main

import (
	"encoding/base64"
	"golang.org/x/net/webdav"
	"log"
	"net/http"
	"os"
	"strings"
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

func isAuth(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return false
	}

	if pair[0] != "username" && pair[1] != "password" {
		return false
	}

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

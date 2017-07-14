package main

import (
	"golang.org/x/net/webdav"
	"log"
	"net/http"
	"os"
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
	log.Printf("INFO using local filesystem at %s", pathRoot)
	return webdav.Dir(pathRoot)
}

func router(h *Handler) func(w http.ResponseWriter, r *http.Request) {
	h.ServeHTTP(w, r)
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
	http.ListenAndServe("127.0.0.1:8080", h)
}

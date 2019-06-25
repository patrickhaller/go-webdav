package main

import (
	"github.com/patrickhaller/slog"
	"net/http"
	"testing"
	"time"
)

func TestAntiDos(t *testing.T) {
	// hasTooManyPasswdAttempts(username string, r *http.Request) bool {
	username := "larry"
	r, _ := http.NewRequest("GET", "/", nil)
	r.Header.Add("X-Forwarded-For", "10.1.1.1")

	cfg.AuthClientsWindow = 60
	cfg.AuthFailWindow = 60
	cfg.AuthFailMaxCount = 1
	cfg.AuthFailLogPer = 1
	slog.Init(slog.Config{
		File:      "STDERR",
		Debug:     true,
		AuditFile: "STDERR",
		Prefix:    "WBDV",
	})

	// first attempt
	if hasTooManyPasswdAttempts(username, r) == true {
		t.Error("blocked on first attempt")
	}
	// ... they provide wrong passwd
	lastFails[username] = append(lastFails[username], client{time: time.Now()})

	if len(lastFails[username]) == 0 {
		t.Error("lastFails is still zero-length")
	}

	if len(currentClients[username]) == 0 {
		t.Error("currentClients is still zero-length")
	}

	// second attempt
	if hasTooManyPasswdAttempts(username, r) == false {
		t.Error("not blocked on second attempt")
	}
}

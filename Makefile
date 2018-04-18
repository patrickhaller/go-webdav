host := webdav.$(shell hostname --domain)
name := go-webdav

restart:
	ssh $(host) systemctl stop $(name) || true
	scp ~/var/go/bin/$(name) $(host):/usr/local/bin/.
	ssh $(host) systemctl start $(name)

include ~/pkg/make/Makefile.golang

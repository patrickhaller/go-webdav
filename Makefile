host := webdav.$(shell hostname --domain)
name := go-webdav

test:
	scp ~/var/go/bin/$(name) $(host):/tmp/.
	ssh -t $(host) /tmp/go-webdav -cf /usr/local/etc/webdav-debug.toml

restart:
	ssh $(host) systemctl stop $(name) || true
	scp ~/var/go/bin/$(name) $(host):/usr/local/bin/.
	ssh $(host) systemctl start $(name)

include ~/pkg/make/Makefile.golang

include Makefile.golang
host = webdav.$(shell hostname --domain)

test: build
	scp $(name) $(host):/tmp/.
	ssh -t $(host) /tmp/go-webdav -cf /usr/local/etc/webdav-debug.toml

restart:
	ssh $(host) rm /usr/local/bin/$(name)
	scp $(name) $(host):/usr/local/bin/.
	ssh $(host) systemctl restart $(name)


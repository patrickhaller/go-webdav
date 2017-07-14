include ~/pkg/make/Makefile.golang
#host := haze.ofs.edu.sg
name := go-webdav

#restart:
#	ssh $(host) systemctl stop $(name) || true
#	scp ~/var/go/bin/$(name) $(host):/usr/local/bin/.
#	ssh $(host) systemctl start $(name)
#
#setup:
#	ssh $(host) mkdir /opt/$(name) || true
#	scp $(name).service $(host):/etc/systemd/system/.
#	ssh $(host) systemctl enable $(name)

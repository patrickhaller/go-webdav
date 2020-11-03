### Features
webdav written in golang with the following features:
   * Multiuser
   * LDAP auth
   * Standalone
   * Anti-DoS and password brute-force client limiting

A patch to x/net/webdav to prevent incomplete directory listing when an unreadable file/directory is encountered.

### References
https://godoc.org/golang.org/x/net/webdav 

https://github.com/vvekic/go-webdav 
	small wrapper on net/webdav

https://github.com/cetex/go-webdav-parallel
	parallel reads for distributed FSs -- e.g. ceph

https://github.com/gogits/webdav
	ab initio implementation

[gohalt](https://github.com/1pkg/gohalt) rate-limiting
   

build: vpncloud.1

vpncloud.1: vpncloud.1.ronn
	ronn -r vpncloud.1.ronn

install:
	install -d $(DESTDIR)/etc/vpncloud
	install -m 600 example.net $(DESTDIR)/etc/vpncloud/example.net
	install -d $(DESTDIR)/var/log
	install -d $(DESTDIR)/run
	install -d $(DESTDIR)/usr/bin
	install -m 755 vpncloud $(DESTDIR)/usr/bin/vpncloud

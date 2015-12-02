build: vpncloud.1

vpncloud.1: vpncloud.1.ronn
	ronn -r vpncloud.1.ronn

install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 vpncloud $(DESTDIR)/usr/bin/vpncloud

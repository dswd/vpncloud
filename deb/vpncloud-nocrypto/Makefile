build: vpncloud.1 vpncloud

vpncloud.1: vpncloud.1.ronn
	ronn -r vpncloud.1.ronn

vpncloud.1.ronn: ../../vpncloud.md
	cp ../../vpncloud.md vpncloud.1.ronn

clean:
	rm -f vpncloud.1* vpncloud ../../target/release/vpncloud

vpncloud: ../../target/release/vpncloud
	cp ../../target/release/vpncloud vpncloud

../../target/release/vpncloud: ../../src/*.rs ../../Cargo.toml ../../src/usage.txt ../../src/c/*
	(cd ../..; cargo build --release)

install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 vpncloud $(DESTDIR)/usr/bin/vpncloud

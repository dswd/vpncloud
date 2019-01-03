PACKAGE=vpncloud
DEPENDENCIES=debhelper devscripts

.PHONY: default
default: clean build

.PHONY: build
build: $(PACKAGE)_*.deb
$(PACKAGE)_*.deb: $(PACKAGE)/vpncloud.1.ronn $(PACKAGE)/vpncloud
	(cd $(PACKAGE); make clean; debuild -b -us -uc; cd ..)

.PHONY: clean
clean:
	(cd $(PACKAGE); debuild -- clean; cd ..)
	rm -rf $(PACKAGE)_*
	rm -f ../target/release/vpncloud

$(PACKAGE)/vpncloud.1.ronn: ../vpncloud.md
	cp ../vpncloud.md $(PACKAGE)/vpncloud.1.ronn

$(PACKAGE)/vpncloud: ../target/release/vpncloud
	cp ../target/release/vpncloud $(PACKAGE)/vpncloud

../target/release/vpncloud: ../src/*.rs ../Cargo.toml
	(cd ..; cargo build --release)

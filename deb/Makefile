PACKAGE=vpncloud
DEPENDENCIES=debhelper devscripts

.PHONY: default
default: clean build

.PHONY: build
build: $(PACKAGE)_*.deb
$(PACKAGE)_*.deb:
	(cd $(PACKAGE); make clean; debuild -b -us -uc; cd ..)

.PHONY: clean
clean:
	(cd $(PACKAGE); debuild clean; cd ..)
	rm -rf $(PACKAGE)_*

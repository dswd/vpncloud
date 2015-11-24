PACKAGE=vpncloud
DEPENDENCIES=debhelper devscripts

.PHONY: default
default: clean build

.PHONY: build
build: $(PACKAGE)_*.deb $(PACKAGE)-nocrypto_*.deb
$(PACKAGE)_*.deb:
	(cd $(PACKAGE); make clean; debuild -b -us -uc; cd ..)
$(PACKAGE)-nocrypto_*.deb:
	(cd $(PACKAGE)-nocrypto; make clean; debuild -b -us -uc; cd ..)

.PHONY: clean
clean:
	(cd $(PACKAGE); debuild clean; cd ..)
	(cd $(PACKAGE)-nocrypto; debuild clean; cd ..)
	rm -rf $(PACKAGE)_* $(PACKAGE)-nocrypto_*

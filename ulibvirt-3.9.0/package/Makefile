LANG=C
PKGNAME=libvirt
RPMBUILD := rpmbuild
PACKAGE:=$(shell pwd)
TOPDIR:=$(shell dirname $(PACKAGE))
MACH :=  $(shell uname -m)
GITID:= $(shell git log --max-count=1 --pretty=format:%H)
RPMVERSION:=3.9.0
BUILD:=5
DIST:=$(shell scripts/dist.sh)
SPECFILE:=$(PKGNAME).spec
RPM:=$(PACKAGE)/rpm
SRPMS:=$(RPM)/SRPMS
SOURCES:=$(RPM)/SOURCES
TESTPATCH:=$(PACKAGE)/sources/$(PKGNAME)-test.patch
FILTERDIFF:=filterdiff -x '*package/*' -x '*/.gitignore' -x '*/makefile' -x '*/Makefile'

STAMP_VERSION := $(RPMVERSION)

LOCVERFILE:=../localversion
# create an empty localversion file if you don't want a local buildid
ifneq ($(wildcard $(LOCVERFILE)),)
  BUILDID:=$(shell cat $(LOCVERFILE))
else
  BUILDID:=$(shell scripts/buildid.sh)
endif
$(info BUILDID is "$(BUILDID)". Update '$(shell dirname $(PACKAGE))/localversion' to change.)

PKGRELEASE:=$(BUILD)$(DIST)$(BUILDID)
SPECRELEASE:=$(BUILD)%{?dist}$(BUILDID)

TARFILE:=$(PKGNAME)-$(RPMVERSION)-$(PKGRELEASE).tar.xz
TARBALL:=$(PACKAGE)/sources/$(TARFILE)

default: help

clean: clean-sources clean-rpmdirs

clean-sources:
	@rm -f $(RPM)/SPECS/*
	@for i in $(SOURCES)/*; do \
		rm -rf $$i; \
	done;

clean-rpmdirs:
	@for i in $(RPM)/{BUILD,SRPMS,RPMS,SPECS}/*; do \
		rm -rf $$i; \
	done;

.PHONY: $(TARBALL)
$(TARBALL):
	@scripts/create-tarball.sh $(GITID) $(TARBALL) $(PKGNAME)-$(RPMVERSION)-$(PKGRELEASE)

setup-source: clean-sources $(TARBALL)
	@cp $(PACKAGE)/sources/SOURCES/* $(SOURCES)/
	@cp $(PACKAGE)/sources/$(SPECFILE).template $(SOURCES)/$(SPECFILE)
	@scripts/genspec.sh $(SOURCES) $(SOURCES)/$(SPECFILE) $(PKGRELEASE) $(RPMVERSION) $(SPECRELEASE)
	@cp $(SOURCES)/$(SPECFILE) $(RPM)/SPECS/
	@cp -l $(TARBALL) $(SOURCES)/ || cp $(TARBALL) $(SOURCES)/
	@touch $(TESTPATCH)
	@git diff --no-renames HEAD > $(TESTPATCH).tmp
	@($(FILTERDIFF) $(TESTPATCH).tmp | egrep -v "^index|^diff" >$(TESTPATCH).tmp2; true)
	@mv $(TESTPATCH).tmp2 $(TESTPATCH).tmp
	@diff $(TESTPATCH).tmp $(TESTPATCH) > /dev/null || \
		echo "WARNING: There are uncommitted changes in your tree or the changes are not in sync with $(PKGNAME)-kvm-test.patch.  Either commit the changes or run 'make test-patch'"
	@rm $(TESTPATCH).tmp
	@cp $(TESTPATCH) $(SOURCES)/

test-patch:
	@git diff --no-renames HEAD > $(TESTPATCH);
	@($(FILTERDIFF) $(TESTPATCH) | egrep -v "^index|^diff" >$(TESTPATCH).tmp; true)
	@mv $(TESTPATCH).tmp $(TESTPATCH);

tarball: $(TARBALL)

all-rpms: setup-source
	$(RPMBUILD) --define "_topdir $(RPM)" \
		    --define "dist $(DIST)" \
		    --target $(MACH) \
		    -ba $(RPM)/SPECS/$(PKGNAME).spec

srpm: setup-source
	$(RPMBUILD) --define "_topdir $(RPM)" \
		    --define "dist $(DIST)" \
		    --nodeps -bs $(RPM)/SPECS/$(PKGNAME).spec

rpms: setup-source
	$(RPMBUILD) --define "_topdir $(RPM)" \
		    --define "dist $(DIST)" \
		    --target $(MACH) \
		    -bb $(RPM)/SPECS/$(PKGNAME).spec

release: clean-sources
	@$(PACKAGE)/scripts/new_release.sh $(RPMVERSION) $(BUILD) $(PACKAGE)
	@$(PACKAGE)/scripts/update_changelog.sh $(RPMVERSION) $(shell echo $$[$(BUILD) + 1]) $(PACKAGE) "$(STAMP_VERSION)-$(PREBUILD)$(shell echo $$[$(BUILD) + 1])"
	@git commit -s Makefile sources/$(PKGNAME).spec.template -m "[ucloud] $(PKGNAME)-$(STAMP_VERSION)-$(PREBUILD)$(shell echo $$[$(BUILD) + 1])"

release-tag:
	@git tag -a -m "$(PKGNAME)-$(STAMP_VERSION)-$(BUILD)" $(PKGNAME)-$(STAMP_VERSION)-$(BUILD)

help:
	@echo  ''
	@echo  'Cleaning targets:'
	@echo  '  clean           - Do clean-sources, clean-rpmdirs'
	@echo  '  clean-sources   - Clean package/rpm/SOURCES/ directory'
	@echo  '  clean-rpmdirs   - Clean package/rpm/{BUILD,SRPMS,RPMS,SPECS} directories'
	@echo  ''
	@echo  'Building targets:'
	@echo  ' All rpm/srpm files will be put under package/rpm/ directory'
	@echo  ''
	@echo  '  srpm:       - Create SRPM under package/rpm/ directory'
	@echo  '  rpms:       - Create binary RPMS under package/rpm/ directory'
	@echo  '  all-rpms:   - Create SRPM and binary RPM under package/rpm/ directory'
	@echo  ''
	@echo  '  tarball:    - Create a tarball'
	@echo  '  test-patch  - Create a diff against HEAD and put it in libvirt-test.patch.'
	@echo  '                Then libvirt-test.patch will be added to the libvirt build'
	@echo  ''
	@echo  'Package maintaining targets:'
	@echo  ' These targets are useful for package maintainers,'
	@echo  ' make sure you know what you are doing before going ahead'
	@echo  ''
	@echo  '  release:      - update package version, changelog, then do a commit'
	@echo  '  release-tag:  - tag the current HEAD after make release'

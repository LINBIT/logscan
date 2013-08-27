SUBDIRS = tests

AM_MAKEFLAGS = --no-print-directory

bin_PROGRAMS = logscan
logscan_SOURCES = \
	buffer.c \
	buffer.h \
	error.c \
	error.h \
	logscan.c \
	list.h \
	xalloc.c \
	xalloc.h
logscan_LDADD = -lm

AM_CFLAGS = -Wall

#distclean-local:
#	rm -rf build

EXTRA_DIST = $(top_srcdir)/.version
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version

.PHONY: gen-ChangeLog
gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then					\
	  $(top_srcdir)/build-aux/gitlog-to-changelog > $(distdir)/cl-t;	\
	  rm -f $(distdir)/ChangeLog;						\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;				\
        fi

rpm: dist
	rpmbuild -ba \
		--define "_topdir $(CURDIR)/build" \
		--define "_sourcedir $(CURDIR)" \
		--clean \
		$(PACKAGE).spec

debian: rpm
	ls -t build/RPMS/*/* | head -n 1 | xargs fakeroot alien

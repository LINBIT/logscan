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

TESTS = \
	tests/all

$(TESTS): logscan

TESTS_ENVIRONMENT = \
	abs_top_srcdir=$(abs_top_srcdir); \
	export abs_top_srcdir; \
	abs_top_builddir=$(abs_top_builddir); \
	export abs_top_builddir;

LOG_COMPILER = \
	$(SHELL)

EXTRA_DIST = \
	$(TESTS) \
	tests/test-lib.sh \
	$(top_srcdir)/.version

BUILT_SOURCES = $(top_srcdir)/.version

#distclean-local:
#	rm -rf build

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

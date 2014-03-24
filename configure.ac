AC_INIT([logscan],
        m4_esyscmd([build-aux/git-version-gen .tarball-version]),
        [Andreas Gruenbacher <agruen@linbit.com>])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_FILES([
	Makefile
	logscan.spec
])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])

AC_PROG_CC
AC_PROG_CC_STDC
AC_CHECK_LIB([pcre], [pcre_compile])
AC_OUTPUT

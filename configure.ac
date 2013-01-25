# (c)  Oblong Industries


# Autoconf setup
AC_PREREQ(2.61)
AC_INIT([https-example],
        [0.1],
        [ppelletier@oblong.com],
        [https-example])

AC_CONFIG_SRCDIR(openssl_hostname_validation.c)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([bld/m4])

#
# Identify the compiler
#
AC_PROG_CC


# Shared lib versioning
# CURRENT, REVISION, AGE
# - library source changed -> increment REVISION
# - interfaces added/removed/changed -> increment CURRENT, REVISION = 0
# - interfaces added -> increment AGE
# - interfaces removed -> AGE = 0
# sets YOVO_LT_LDFLAGS
AS_LIBTOOL(YOVO, 2, 0, 0)
LT_INIT

AM_CONDITIONAL([ENABLE_SHARED], [test "x$enable_shared" != xno])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_COLOR_TESTS], [AM_COLOR_TESTS([yes])])

# check for libevent
PKG_CHECK_MODULES([LIBEVENT], [libevent >= 2.1.2
                               libevent_pthreads >= 2.1.2
                               libevent_openssl >= 2.1.2])
AC_SUBST(LIBEVENT_LIBS)
AC_SUBST(LIBEVENT_CFLAGS)

# Makefile generation
AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT

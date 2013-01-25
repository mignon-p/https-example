# (c)  Oblong Industries #

AUTOMAKE_OPTIONS = \
  foreign \
  1.9 \
  --warnings=all \
  --warnings=error \
  --warnings=no-portability

ACLOCAL_AMFLAGS = -I bld/m4

noinst_PROGRAMS = \
  https-client \
  https-server \
  #

https_client_SOURCES = \
  https-client.c \
  https-common.c \
  openssl_hostname_validation.c \
  #

https_server_SOURCES = \
  https-server.c \
  https-common.c \
  #

noinst_HEADERS = \
  https-common.h \
  openssl_hostname_validation.h \
  #

AM_CFLAGS = $(LIBEVENT_CFLAGS) $(OPENSSL_CFLAGS)
AM_LDFLAGS = $(OPENSSL_LDFLAGS) $(LIBEVENT_LIBS) $(OPENSSL_LIBS)

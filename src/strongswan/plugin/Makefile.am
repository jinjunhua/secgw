AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS  = -I ../../m4

# strongSwan plugin Makefile
plugin_LTLIBRARIES = libstrongswan-gm.la

libstrongswan_gm_la_SOURCES = \
    gm_plugin.c        \
    gm_sm4_crypter.c   \
    gm_sm3_hasher.c    \
    gm_hmac_sm3_prf.c  \
    gm_sm2_ke.c        \
    ../../crypto/sm2.c \
    ../../crypto/sm3.c \
    ../../crypto/sm4.c

libstrongswan_gm_la_CFLAGS = \
    $(AM_CFLAGS) \
    -I$(srcdir)/../../

libstrongswan_gm_la_LDFLAGS = \
    $(AM_LDFLAGS) \
    -module -avoid-version \
    -export-symbols-regex gm_plugin_create

plugindir = $(ipsecdir)/plugins
plugin_DATA = libstrongswan-gm.la

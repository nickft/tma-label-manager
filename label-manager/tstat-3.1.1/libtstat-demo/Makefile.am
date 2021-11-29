if LIBTSTAT
    target = demo
else
    target =
endif
AM_CFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = $(target)
bin_PROGRAMS = $(target)
demo_SOURCES = \
    pcapwrapper.c demo.c\
    pcapwrapper.h
demo_LDFLAGS = -Wl,--rpath -Wl,$(top_srcdir)/libtstat/.libs
demo_LDADD = $(top_srcdir)/libtstat/.libs/libtstat.so
EXTRA_DIST = tstat.conf configure.ac

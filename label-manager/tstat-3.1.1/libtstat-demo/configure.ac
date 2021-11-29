#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Note: this file is provided only as example
#       and is not used in the building process of libtstat-demo

AC_PREREQ(2.61)
AC_INIT([libtstat_demo], [1.0], [<mellia@mail.tlc.polito.it> <rossi@mail.tlc.polito.it>])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([demo.c])
AC_PROG_CC
AC_PROG_LIBTOOL

## check for library
AC_CHECK_LIB([m],      [log],,               AC_MSG_ERROR([missing 'm' library]))
AC_CHECK_LIB([pcap],   [pcap_open_live],,    AC_MSG_ERROR([missing 'pcap' library]))
AC_CHECK_LIB([tstat],  [tstat_next_pckt],,   AC_MSG_ERROR([missing 'tstat' library]))
AC_CHECK_LIB([pthread],[pthread_mutex_lock],,AC_MSG_ERROR([missing 'pthread' library]))

AC_CONFIG_FILES(Makefile)
AC_OUTPUT

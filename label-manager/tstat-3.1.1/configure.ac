#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ(2.61)

# define variables for version numbers
m4_define([_version_major], [3])
m4_define([_version_minor], [1])
m4_define([_version_bugfix], [1])
m4_define([_version_date], ["Tue May 17 14:41:53 CEST 2016"])
m4_define([_version_flavor], ["Hindenburg"])
m4_define([_libtstat_version], [1.0.0])

AC_INIT([tstat], 
        m4_esyscmd([echo _version_major._version_minor._version_bugfix | tr -d '\n']),
        [mellia@polito.it, munafo@polito.it])

AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([tstat/tstat.c])

#AC_CONFIG_SUBDIRS([DPMI_utils
#                   lib-demo
#                   src])

# define statement for version numbers
AC_DEFINE([VERSION_MAJOR], [_version_major], [Package major number])
AC_DEFINE([VERSION_MINOR], [_version_minor], [Package minor number])
AC_DEFINE([VERSION_BUGFIX], [_version_bugfix], [Package bugfix number])
AC_DEFINE([VERSION_DATE], [_version_date], [Package date])
AC_DEFINE([VERSION_FLAVOR], [_version_flavor], [Package flavor])
AC_CONFIG_HEADER([config.h])


#AC_CANONICAL_SYSTEM

m4_pattern_allow([AC_LBL_C_INIT (V_CCOPT, V_INCLS)])

## Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET


## See if "unsigned long long int" works
AC_CHECK_SIZEOF(unsigned long long int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned short)


## include additional checking if developing
m4_pattern_allow([AC_LBL_DEVEL(V_CCOPT)])

## check for needed network libraries
m4_pattern_allow([AC_LBL_LIBRARY_NET()])

## use fpurge if available, otherwise fflush
AC_CHECK_FUNCS(fpurge)

## use mkstemp if available, otherwise tempnam
AC_CHECK_FUNCS(mkstemp)

## check for the IPv6 routines inet_pton
AC_CHECK_FUNCS(inet_pton)

## Grab includes from ./cygwin-includes under Windows versions
PCAP_LDLINK="-lpcap"
case "$target" in
  *cygwin*)	V_INCLS="$V_INCLS -I./cygwin-includes";
            V_DEFINES="$V_DEFINES -D__USE_BSD -D__FAVOR_BSD -D__USE_MISC -D__WIN32";
            PCAP_LDLINK="-lwpcap"
esac

## Checks for libraries
AC_CHECK_LIB([m], [log],, AC_MSG_ERROR([missing 'm' library]))
#AC_CHECK_LIB([pthread], [pthread_cond_init],,AC_MSG_ERROR([missing 'pthread' library]))

## --enable-android option
ENABLE_ANDROID=no
AC_ARG_ENABLE(android, 
    AS_HELP_STRING([--enable-android], [ignore the pthread test for Android compilation]),
    ENABLE_ANDROID=$enableval)
AM_CONDITIONAL([ANDROID], [test "x$ENABLE_ANDROID" = "xyes"])
if test ".${ENABLE_ANDROID}" = ".no"; then
   AC_CHECK_LIB([pthread], [pthread_cond_init],,AC_MSG_ERROR([missing 'pthread' library]))
fi

##AM_COND_IF([ANDROID],,
##           [AC_CHECK_LIB([pthread], [pthread_cond_init],,AC_MSG_ERROR([missing 'pthread' library]))])

## --enable-libtstat option
ENABLE_LIBTSTAT=no
AC_ARG_ENABLE(libtstat, 
    AS_HELP_STRING([--enable-libtstat], [generate a shared library from tstat code]),
    ENABLE_LIBTSTAT=$enableval)
AM_CONDITIONAL([LIBTSTAT], [test "x$ENABLE_LIBTSTAT" = "xyes"])

## --enable-debug option
#ENABLE_DEBUG=yes
#AC_ARG_ENABLE(debug,
#    AS_HELP_STRING([--enable-debug], [compile with debug support]),
#    ENABLE_DEBUG=$enableval)
#if test "xENABLE_DEBUG" = "xyes"; then
#    DEBUG_CFLAGS = -g -ggdb
#fi
#AM_CONDITIONAL([DEBUG], [test "x$ENABLE_DEBUG" = "xyes"])

## --enable-rrdthread option
ENABLE_RRDTHREAD=no
AC_ARG_ENABLE(rrdthread,
    AS_HELP_STRING([--enable-rrdthread], [RRD I/O on a separate thread (requires Linux>=2.6.35)]),
    ENABLE_RRDTHREAD=$enableval)
if test "x$ENABLE_RRDTHREAD" = "xyes"; then
    V_DEFINES="$V_DEFINES -DRRD_THREADED"
fi
AM_CONDITIONAL([RRDTHREAD], [test "x$ENABLE_RRDTHREAD" = "xyes"])

dnl look for pcap library
dnl add ./configure option to specify libpcap path
# AC_ARG_WITH(  pcap-root,
#               [  --with-pcap-root=DIR        LBNL pcap located in DIR],
#               PCAP_INCLUDE="$withval" PCAP_LIB="$withval",
#              PCAP_LIB= PCAP_INCLUDE=)
#AC_ARG_WITH(  pcap-lib,
#              [  --with-pcap-lib=DIR          or libpcap located in DIR],
#              PCAP_LIB="$withval")
#AC_ARG_WITH(  pcap-include,
#              [  --with-pcap-include=DIR      or pcap.h located in DIR],
#              PCAP_INCLUDE="$withval")
#
#if (test ".${PCAP_LIB}" != "."      &&
#    test ! -d ${PCAP_LIB})              ||
#   (test ".${PCAP_INCLUDE}" != "."  &&
#    test ! -d ${PCAP_INCLUDE}); then
#    echo
#    echo "*******************************************************************"
#    echo "*"
#    echo "* ERROR:    You specified or implied a non-existent directory for"
#    echo "*           libpcap:"
#    echo "*               --with-pcap-lib=${PCAP_LIB}"
#    echo "*               --with-pcap-include=${PCAP_INCLUDE}"
#    echo "*"
#    echo "*>>> Continuing without libpcap is impossible."
#    echo "*"
#    echo "*???     1. Correct the --with-pcap-xxxxx option and rerun"
#    echo "*???        ./configure"
#    echo "*"
#    echo "*******************************************************************"
#    echo
#    exit 1
#else
#    if (test "${PCAP_INCLUDE}" != "");then
#         V_PCAP_INCLUDE=-I[${PCAP_INCLUDE}];
#    fi
#    if (test "${PCAP_INCLUDE}" != "");then
#         V_PCAP_LIBPATH=-L[${PCAP_LIB}];
#    fi
#fi

###################################
## Libpcap
AC_CHECK_HEADERS([pcap.h])

## at least one of the two headers must be present
AC_CHECK_HEADERS([net/bpf.h])
AC_CHECK_HEADERS([pcap-bpf.h])

AC_CHECK_LIB([pcap], [pcap_open_live],,AC_MSG_ERROR([missing 'pcap' library]))

if test ".${ac_cv_header_pcap_h}" != ".yes" ||
   (test ".${ac_cv_header_net_bpf_h}" != ".yes" &&
    test ".${ac_cv_header_pcap_bpf_h}" != ".yes" ) 
   then
    echo
    echo "*******************************************************************"
    echo "*"
    echo "* ERROR: pcap header, or library are missing."
    echo "*        At least one of bpf header must be found."
    echo "*        (yes == found, no == NOT found)"
    echo "*"
    echo "*        pcap.h.......................${ac_cv_header_pcap_h}"
    echo "*        pcap-bpf.h...................${ac_cv_header_pcap_bpf_h}"
    echo "*        net/bpf.h....................${ac_cv_header_net_bpf_h}"
    echo "*        pcap_open_live() in -lpcap...${ac_cv_lib_pcap_pcap_open_live}"
    echo "*"
    echo "*>>> No way to proceed."
    echo "*"
    echo "*???     1. Install libpcap and rerun ./configure"
#    echo "*???  or 2. Use the --with-pcap-root= option"
    echo "*"
    echo "*******************************************************************"
    echo
    AC_MSG_ERROR(Unable to continue... aborting ./configure)
fi


dnl define _BSD_SOURCE for libc-2
if [[ -f /lib/libc-2* ]]; then
 V_DEFINES="$V_DEFINES -D_BSD_SOURCE"
else
 if [[ -f /lib64/libc-2* ]]; then
 V_DEFINES="$V_DEFINES -D_BSD_SOURCE"
 else
   ls -1 /lib/*/libc-2* > /dev/null 2>&1
   if [[ "$?" = "0" ]]; then
     V_DEFINES="$V_DEFINES -D_BSD_SOURCE"
   fi
 fi
fi

dnl define __FAVOR_BSD when compiling for Android
if test ".${ENABLE_ANDROID}" = ".yes"; then
     V_DEFINES="$V_DEFINES -D__FAVOR_BSD"
fi

#####################
## RRD library
AC_CHECK_LIB([rrd], [rrd_init], [AC_CHECK_HEADERS(rrd.h, have_rrd=yes, have_rrd=no)], [have_rrd=no])
if test "x$have_rrd" = "xyes"; then
    V_DEFINES="$V_DEFINES -DHAVE_RRDTOOL"
    LIBS="$LIBS -lrrd"
fi

######################
## ZLIB library
## --enable-zlib option
ENABLE_ZLIB=no
AC_ARG_ENABLE(zlib, 
    AS_HELP_STRING([--enable-zlib], [enable zlib support to generate compressed data]),
    ENABLE_ZLIB=$enableval)
AM_CONDITIONAL([ZLIB], [test "x$ENABLE_ZLIB" = "xyes"])
if test ".${ENABLE_ZLIB}" = ".yes"; then
  AC_CHECK_LIB([z], [gzopen], [AC_CHECK_HEADERS(zlib.h, have_zlib=yes, have_zlib=no)], [have_zlib=no])
  if test "x$have_zlib" = "xyes"; then
    V_DEFINES="$V_DEFINES -DHAVE_ZLIB"
    LIBS="$LIBS -lz"
  fi
else
  have_zlib=no
fi


AC_SUBST(V_CCOPT)
AC_SUBST(V_INCLS)

#AC_SUBST(V_PCAP_LDLIBS)
#AC_SUBST(V_PCAP_INCLUDE)
#AC_SUBST(V_PCAP_LIBPATH)

AC_SUBST(V_DEFINES)
AC_SUBST(LIBTSTAT_VERSION, _libtstat_version)
AC_SUBST(PCAP_LDLINK)
#AC_SUBST(RRD_LDLINK)
AC_SUBST(PACKAGE_VERSION)

AC_CONFIG_FILES([
    Makefile
    tstat/Makefile
    libtstat/Makefile
    libtstat/libtstat.pc
    libtstat-demo/Makefile
    README
    NEWS
])
AC_OUTPUT

echo \
"-------------------------------------------------
  ${PACKAGE_NAME} Version ${PACKAGE_VERSION}
  ${LIBS}

  Prefix: '${prefix}'

  Package features:
    - pcap      yes
    - zlib      ${have_zlib}
    - rrd       ${have_rrd}
    - libtstat  ${ENABLE_LIBTSTAT}
    - rrdthread ${ENABLE_RRDTHREAD}
--------------------------------------------------"

DEFINES = @V_DEFINES@

##################################################
## User information
#
DEFINES += -DBUILT_USER="\"`whoami`\"" 
DEFINES += -DBUILT_HOST="\"`hostname`\"" 
DEFINES += -DBUILT_DATE="\"`date`\""

include Makefile.conf


################################################################## 
#
# If you do not want to use Tstat/RRDTool integration, comment
# out the lines below. You may also want to check RRDTool version
# and path are coherent with your system settings
# 
################################################################## 
#DEFINES += -DHAVE_RRDTOOL
#RRD_VER     = 1.2.9
#RRD_LDLIBS  = -lrrd
#RRD_LDFLAGS = -L/usr/local/lib/ -L/usr/local/rrdtool/lib/  -L/usr/local/rrdtool-${RRD_VER}/lib/ 
#RRD_INCS    = -I/usr/local/rrdtool/include/ -I/usr/local/rrdtool-${RRD_VER}/include

################################################################## 
# defined.
# defined.
# 
# Just a quick installation rule, not much to do
# 
################################################################## 
# Pathname of directory to install the binary
BINDIR = /usr/local/bin
MANDIR = /usr/local/man/


################################################################## 
################################################################## 
################################################################## 
# 
# You shouldn't need to change anything below this point
# 
################################################################## 
################################################################## 
################################################################## 

#PCAP_LDLIBS = @V_PCAP_LDLIBS@
#PCAP_INCS    = @V_PCAP_INCLUDE@
#PCAP_LDFLAG = @V_PCAP_LIBPATH@

CC = @CC@
CCOPT = -Wall @V_CCOPT@
# 
# optimization-1.2.0
# CCOPT = -Wall -O2 -finline-functions -funroll-all-loops -march=pentium4 -mfpmath=sse
#


# Standard CFLAGS
# Probably want full optimization
# FreeBSD needs	-Ae
# HP needs	-Ae
AM_CFLAGS = $(CCOPT) $(DEFINES) -g -ggdb

# Standard LIBS
LDLIBS = @LIBS@ ${PCAP_LDLIBS} ${DPMI_LDLIBS}
# for solaris, you probably want:
#	LDLIBS = -lpcap -lnsl -lsocket -lm
# for HP, I'm told that you need:
#	LDLIBS = -lpcap -lstr -lm
# everybody else (that I know of) just needs:
#	LDLIBS = -lpcap -lm
# 
AM_LDFLAGS = ${PCAP_LDFLAG} ${DAGAPI_LDFLAGS} ${DPMI_LDFLAGS}



# for profiling (under Solaris, at least)
#AM_CFLAGS	+= -pg
#AM_LDFLAGS += /usr/lib/libdl.so.1

# for multithread 
#AM_LDFLAGS += -pthread

# Source Files
include Makefile.sources

bin_PROGRAMS = tstat
tstat_SOURCES = ${HDR_FILES} ${CFILES}
tstat_LDFLAGS = ${AM_LDFLAGS}
tstat_LDADD = ${LDLIBS}

clean-local:
	list=`ls .deps` ; test -z $(list) || rm -f $(list)

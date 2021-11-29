SUBDIRS = tstat libtstat libtstat-demo
EXTRA_DIST = doc tstat-conf autogen.sh

dist-hook:
	rm -rf `find $(distdir) -name .svn`


# this target remove the HOWTO-BUILD directory
# from the distribution tarball which contains
# building stuff for the documentation
#dist-hook:
#	rm -rf $(distdir)/doc/HOWTO-BUILD

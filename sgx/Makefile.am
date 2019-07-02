MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =	-I$(top_srcdir)/src/lib \
		-I$(top_srcdir)/src/lib/pkcs11 \
		-I$(top_srcdir)/src/lib/common \
		-I$(top_srcdir)/src/lib/crypto \
		-I$(top_srcdir)/src/lib/data_mgr \
		-I$(top_srcdir)/src/lib/object_store \
		-I$(top_srcdir)/src/lib/slot_mgr \
		-I$(top_srcdir)/src/lib/session_mgr \
		-I$(top_srcdir)/src/lib/token_mgr \
		-I$(top_srcdir)/src/lib/handle_mgr \
		-I$(top_srcdir)/src/lib/hard_token_sgx

noinst_LTLIBRARIES =		libsofttoken.la
libsofttoken_la_SOURCES =	\
				SgxTokenModule.cpp \
				SgxToken.cpp \
				ObjectHandler.cpp \
				CryptoHandler.cpp \
				KeyHandler.cpp

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
                        $(srcdir)/*.h

AC_INIT([ietf-ipsec], [0.1], [gabilm@um.es])
AC_PROG_CC


AC_SUBST([TARGET],"ietf-ipsec")
CFLAGS="-Wall -w  -O3 -fPIC"

AC_CHECK_HEADERS(crypt.h, [], [AC_ERROR([A working crypt is required])])
AC_SEARCH_LIBS(crypt, crypt, [], [AC_ERROR([A working crypt is required])])

AC_CHECK_HEADERS(pthread.h, [], [AC_ERROR([A working pthread is required])])
AC_SEARCH_LIBS(pthread_create, pthread, [], [AC_ERROR([A working pthread is required])])

AC_CHECK_HEADERS(sysrepo.h, [], [AC_ERROR([A working sysrepo is required])])
AC_SEARCH_LIBS(sr_connect, sysrepo, [], [AC_ERROR([A working sysrepo is required])])

  
AC_CHECK_HEADERS(libvici.h, [], [AC_ERROR([A working libvici is required])])
AC_SEARCH_LIBS(connect, vici, [], [AC_ERROR([A working libvici is required])])
  
AC_SUBST([LIBVICI],"-lvici -L/usr/lib/ipsec/")
  
AC_SUBST([DEPS],"base/utils.h \
  		base/sysrepo_utils.h \
  		base/log.h \
  		base/spd_entry.h \
  		base/spa_entry.h \
  		base/pad_entry.h \
  		base/ikev2_entry.h \
  		base/pfkeyv2_entry.h")
		
AC_SUBST([OBJ],"base/utils.o \
	base/sysrepo_utils.o \
	base/log.o \
	base/spd_entry.o \
	base/sad_entry.o \
	base/pad_entry.o \
	base/ikev2_entry.o \
	base/pfkeyv2_entry.o ")
  
AC_CONFIG_FILES([Makefile])

AC_OUTPUT

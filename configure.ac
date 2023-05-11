#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([pipewire-module-xrdp], [0.1], [xrdp-devel@googlegroups.com])
# specify config_ac.h for familiarity
AC_CONFIG_HEADERS([config_ac.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])

AM_PROG_AR
AM_INIT_AUTOMAKE([-Wall foreign silent-rules])
AM_SILENT_RULES([yes])

PKG_PROG_PKG_CONFIG
if test "x$PKG_CONFIG" = "x"; then
  AC_MSG_ERROR([pkg-config not found])
fi

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Default system-wide autostart directory from XDG autostart specification
m4_define([XDG_AUTOSTART_DIR], /etc/xdg/autostart)

# Build shared libraries
LT_INIT([shared disable-static])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Checks for libraries.
PKG_CHECK_MODULES([PW], [libpipewire-0.3 >= 0.3.58], [],
        [AC_MSG_ERROR([please install libpipewire-0.3-dev or pipewire-devel])])
PKG_CHECK_MODULES([SPA], [libspa-0.2], [],
        [AC_MSG_ERROR([please install libspa-0.2-dev or pipewire-devel])])

PW_MODDIR=`$PKG_CONFIG --variable=moduledir libpipewire-0.3`

# use the prefix as same as pipewire
AC_PREFIX_PROGRAM(pw)

AC_ARG_WITH(
    [module-dir],
    [AS_HELP_STRING([--with-module-dir],
        [Directory where to install the modules to (defaults to `$PKG_CONFIG --variable=moduledir libpipewire-0.3`)])],
    [modlibexecdir=$withval], [modlibexecdir="${PW_MODDIR}"])
AC_SUBST(modlibexecdir)

AC_ARG_WITH(
    [xdgautostart-dir],
    [AS_HELP_STRING([--with-xdgautostart-dir],
        [Directory to install the desktop file (defaults to XDG_AUTOSTART_DIR)])],
    [xdgautostartdir=$withval], [xdgautostartdir=XDG_AUTOSTART_DIR])
AC_SUBST(xdgautostartdir)

AC_ARG_ENABLE(
    [alt-pw-cli],
    [AS_HELP_STRING([--enable-alt-pw-cli],
        [Enable the alternate ps-cli command (yes/no/auto)])],
        [alt_pw_cli=$enableval], [alt_pw_cli=auto])

# The alternative pw-cli is not needed for pipewire 0.3.59 and
# later.
# See https://gitlab.freedesktop.org/pipewire/pipewire/-/issues/2709
if test x$alt_pw_cli = xauto; then
    if  $PKG_CONFIG --atleast-version 0.3.59 libpipewire-0.3; then
        AC_MSG_NOTICE([The alternative pw-cli will not be used])
        alt_pw_cli=no
    else
        AC_MSG_NOTICE([The alternative pw-cli will be used])
        alt_pw_cli=yes
    fi
fi

AM_CONDITIONAL(USE_ALT_PW_CLI, [test "x$alt_pw_cli" = xyes])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 instfiles/Makefile])
AC_OUTPUT

AM_CFLAGS = 
AM_LDFLAGS =

if USE_ALT_PW_CLI
pkglibexec_PROGRAMS = cli_0358_mod
endif

modlibexec_LTLIBRARIES = libpipewire-module-xrdp-pipewire.la

cli_0358_mod_SOURCES = pw-cli_0358_mod.c
cli_0358_mod_CFLAGS =  $(PW_CFLAGS) $(SPA_CFLAGS)
cli_0358_mod_LDFLAGS = $(PW_LIBS)

libpipewire_module_xrdp_pipewire_la_SOURCES = module-xrdp-pipewire.c
libpipewire_module_xrdp_pipewire_la_CFLAGS = $(PW_CFLAGS) $(SPA_CFLAGS) -fPIC
libpipewire_module_xrdp_pipewire_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = \
   load_pw_modules.sh \
   pipewire-xrdp.desktop.in

#
# substitute directories in service file
#
CLEANFILES= \
   pipewire-xrdp.desktop

SUBST_VARS = sed \
   -e 's|@pkglibexecdir[@]|$(pkglibexecdir)|g'

subst_verbose = $(subst_verbose_@AM_V@)
subst_verbose_ = $(subst_verbose_@AM_DEFAULT_V@)
subst_verbose_0 = @echo "  SUBST    $@";

SUFFIXES = .in
.in:
	$(subst_verbose)$(SUBST_VARS) $< > $@

#
# files for all platforms
#
xdgautostart_DATA = \
  pipewire-xrdp.desktop

pkglibexec_SCRIPTS = \
  load_pw_modules.sh

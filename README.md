# pipewire-module-xrdp

Thanks to @Hiero32 who contributed this module.

This module allows xrdp to generate sound on a pipewire-based system.

Pipewire versions 0.3.58 and later are supported.

# Files
## Sources
- [src/module-xrdp-pipewire.c](src/module-xrdp-pipewire.c)
    The module source.
- [src/pw-cli_0358_mod.c](src/pw-cli_0358_mod.c)
    pw-cli for older systems running pipewire 0.3.58

## Other
- [instfiles/load_pw_modules.sh](instfiles/load_pw_modules.sh)
    Shell script invoked when the desktop starts to load the pipewire
    module on xrdp connections.
- [instfiles/pipewire-xrdp.desktop.in](instfiles/pipewire-xrdp.desktop.in)
    Templated file which uses the desktop XDG autostart mechanism to
    run load_pw_modules.sh when a desktop is started.

# Installing a build environment and dependencies
## Debian and derivatives
```sh
# Install build environment
sudo apt install git pkg-config autotools-dev libtool make gcc

# Install dependencies
sudo apt install libpipewire-0.3-dev libspa-0.2-dev
```

## Fedora
```sh
# Install build environment
sudo dnf install git gcc make autoconf libtool automake pkgconfig

# Install dependencies
sudo dnf install pipewire-devel
```

# Building and installing

```
./bootstrap
./configure
make
# Install
sudo make install
```

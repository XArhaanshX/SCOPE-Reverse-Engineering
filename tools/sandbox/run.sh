#!/bin/sh
# usage: run.sh <cmd...>   — runs inside a no-network, read-only sandbox; only /work is writable
# SANDBOX defaults to /tmp/zlsb; put the exe in $SANDBOX/work and dump.py in $SANDBOX/scripts.
SANDBOX=${SANDBOX:-/tmp/zlsb}
exec bwrap --unshare-all --die-with-parent --new-session \
  --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 --symlink usr/bin /bin --symlink usr/bin /sbin \
  --ro-bind /etc/ld.so.cache /etc/ld.so.cache --ro-bind /etc/fonts /etc/fonts \
  --proc /proc --dev /dev --tmpfs /tmp \
  --bind $SANDBOX/work /work --ro-bind $SANDBOX/scripts /scripts --chdir /work \
  --clearenv --setenv HOME /work --setenv WINEPREFIX /work/prefix --setenv WINEDEBUG -all \
  --setenv PATH /usr/bin --setenv WINEDLLOVERRIDES "mscoree,mshtml=" \
  "$@"

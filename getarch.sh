#!/bin/sh

ARCH=`uname -m`
if echo $ARCH | grep '^i.86$' >/dev/null 2>/dev/null; then
  ARCH=ia32
fi

OS=`uname|tr [A-Z] [a-z]`

if [ "x$1" = "x-os" ]; then
  echo $OS
elif [ "x$1" = "x-arch" ]; then
  echo $ARCH
fi

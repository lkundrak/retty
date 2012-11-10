#!/bin/sh

# 'Ah yes, I recognized the name. I recollect the time when young Frodo Baggins
# was one of the worst young rascals of Buckland. But it wasn't mushrooms I was
# thinking of. I had just heard the name Baggins before you turned up. What do
# you think that funny customer asked me?'

check_support() {
  if [ ! -f arch/attach-$1.[cS] ]; then
    ARCH="none"
    OS="none"
  fi
}

ARCH=`uname -m`
if echo $ARCH | grep '^i.86$' >/dev/null 2>/dev/null; then
  ARCH=ia32
fi
if echo $ARCH | grep '^armv.*l$' >/dev/null 2>/dev/null; then
  ARCH=arm
fi

OS=`uname|tr [A-Z] [a-z]`

check_support $ARCH-$OS

if [ "x$1" = "x-os" ]; then
  echo $OS
elif [ "x$1" = "x-arch" ]; then
  echo $ARCH
fi

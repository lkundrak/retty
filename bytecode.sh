#!/bin/bash

state=0
while read X; do
  IFS=""
  X=`echo $X | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'`
  if expr match "$X" '[0-9a-f]* <[^>]*>:' >/dev/null; then
    state=1;
  elif [ $state -gt 0 ]; then
   P=`echo $X | sed 's/\\$/\\\\$/g ; s/\([0-9a-f]*\):\t\(.*\)\t\(.*\)$/C="\1"\nA="\2"\nB="\3"/'`
   eval $P
   A=`echo $A | sed 's/[^0-9a-f]//g ; s/\([0-9a-f]\{2\}\)/0x\1,/g'`
   printf "/* %04s */\t%30s\t/* %s */\n" $C $A $B
  fi
done

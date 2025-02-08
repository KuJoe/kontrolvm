#!/bin/sh
# Script Name:  iolimits

if mkdir /home/kontrolvm/iolock; then
  for i in `/bin/ls /home/kontrolvm/iow/`; do
        sudo /bin/sh /home/kontrolvm/iow/$i
  done
  rm -rf /home/kontrolvm/iolock
else
  echo "Lock failed - exit" >&2
  exit 1
fi
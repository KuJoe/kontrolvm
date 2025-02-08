#!/bin/sh
# Script Name:  killconsole

PID=`ps -ef | grep "websockify" | grep "localhost:$1" | awk '{print $2}'`
for i in $PID; do sleep 2;
    sudo /bin/kill -9 $PID;
done
#!/bin/bash

PREFIX=/home/tqj/downloads/android-ndk-r10
ROOTDIR=/home/hexstia/jni
LINUX_LIBARYSO=/-I/usr/jdk1.6.0_23/include/ -I/usr/jdk1.6.0_23/include/linux/  -I$ROOTDIR
######################################################
CC="$PREFIX/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gcc"

NDK="$PREFIX/platforms/android-14/arch-arm"

CFLAGS="-I$NDK/usr/include"

LDFLAGS="-nostdlib -Wl,-rpath-link=$NDK/usr/lib -L$NDK/usr/lib $NDK/usr/lib/crtbegin_dynamic.o -lc"
###########################################################################################

$CC -o deapk deapk.c $CFLAGS $LDFLAGS
cp deapk /media/disk/


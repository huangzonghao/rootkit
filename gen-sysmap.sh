#!/usr/bin/env bash
grep -E '(D|R|T)' /boot/System.map-$(uname -r) | grep -Ev '(CSWTCH|HYPERVISOR_physdev_op)' | awk '{ print "#define", $3, "((void*)0x" $1 ")"; }' | sed 's/\./_/g' > sysmap.h

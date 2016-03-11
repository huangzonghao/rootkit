# TCP Port Scanner

## Description

This program is for checking the open ports of the given host, either by the hostname or the IP address.

## Build

Use `cmake` as the building tool. 

    cd /path/to/the/src/folder
    mkdir build
    cd build
    cmake ..
    make
    ./portScanner <command>

## Commands

    Usage: <command>
    Command:
    -s Set the starting port, default = 1
    -e Set the ending port, default = 65535
    -p Input the IP address of the host. And note whenever -p is set, any -h , -l settings will be ignored
    -w Input the hostname directly
    -l Check the open ports on the local host
    -v Verbose, prints all the ports status including both the open ports and the closed ports
    -h Print this list;

## Examples
* To checkout the all the open ports of the local machine
    * `./portScan -l`
* To checkout the open ports of `127.0.0.1` between 1 and 10
    * `./portScan -s 1 -e 10 -p 127.0.0.1`
* To checkout the open ports of `www.website.com` between 1 and 10
    * `./portScan -s 1 -e 10 -w www.website.com`

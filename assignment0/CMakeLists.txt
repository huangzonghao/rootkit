cmake_minimum_required ( VERSION 2.8)

file( GLOB_RECURSE  HDR  *.h )
SET (CPP portScanner.cpp)

ADD_EXECUTABLE(portScanner ${CPP} ${HDR})



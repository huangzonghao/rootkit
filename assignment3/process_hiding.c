/*
 *  Assignment 3
 *  Process Hiding
 *
 *  Requirements:
 *     a) Hide processes from the user in such a way that they are still scheduled.
 *     b) Tasks to hide should be identified by an array of PIDs passed to the
 *         module on the command line when loading the module
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <asm/paravirt.h>
#include <linux/moduleparam.h>
#include "sysmap.h"

/* handle at most 10 inputs once */
int pid[10];
int var_count = 0;
module_param_array(pid, int, &var_count, 0000);

int init_module(void){
    int i;
    printk(KERN_INFO "Process_hiding loaded.\n");

    for (i = 0; i < var_count; ++i){
        printk("the %dth number is : %d\n", i, pid[i]);
    }

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Process_hiding unloaded.\n");

    return;
}


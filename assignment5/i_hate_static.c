#define module_mutex *(struct mutex*)SM_module_mutex

void set_page_attributes(void *start, void *end, int (*set)(unsigned long start, int num_pages))
{
        unsigned long begin_pfn = PFN_DOWN((unsigned long)start);
        unsigned long end_pfn = PFN_DOWN((unsigned long)end);

        if (end_pfn > begin_pfn)
                set(begin_pfn << PAGE_SHIFT, end_pfn - begin_pfn);
}

static void unset_module_core_ro_nx(struct module *mod)
{
        set_page_attributes(mod->module_core + mod->core_text_size,
                mod->module_core + mod->core_size,
                SM_set_memory_x);
        set_page_attributes(mod->module_core,
                mod->module_core + mod->core_ro_size,
                SM_set_memory_rw);
}

static void unset_module_init_ro_nx(struct module *mod)
{
        set_page_attributes(mod->module_init + mod->init_text_size,
                mod->module_init + mod->init_size,
                SM_set_memory_x);
        set_page_attributes(mod->module_init,
                mod->module_init + mod->init_ro_size,
                SM_set_memory_rw);
}

static void module_unload_free(struct module *mod)
{
        struct module_use *use, *tmp;

        mutex_lock(&module_mutex);
        list_for_each_entry_safe(use, tmp, &mod->target_list, target_list) {
                struct module *i = use->target;
                pr_debug("%s unusing %s\n", mod->name, i->name);
                module_put(i);
                list_del(&use->source_list);
                list_del(&use->target_list);
                ((void (*)(const void*))SM_kfree)(use);
        }
        mutex_unlock(&module_mutex);
}

/*
static void mod_sysfs_teardown(struct module *mod)
{
        del_usage_links(mod);
        module_remove_modinfo_attrs(mod);
        module_param_sysfs_remove(mod);
        kobject_put(mod->mkobj.drivers_dir);
        kobject_put(mod->holders_dir);
        mod_sysfs_fini(mod);
}
*/

/* Free a module, remove from lists, etc. */
static void free_module(struct module *mod)
{
//        trace_module_free(mod);

//        mod_sysfs_teardown(mod);

        /* We leave it in list to prevent duplicate loads, but make sure
         * that noone uses it while it's being deconstructed. */
        mutex_lock(&module_mutex);
        mod->state = MODULE_STATE_UNFORMED;
        mutex_unlock(&module_mutex);

        /* Remove dynamic debug info */
        ((typeof(&ddebug_remove_module))SM_ddebug_remove_module)(mod->name);

        /* Arch-specific cleanup. */
        ((void (*) (struct module*))SM_module_arch_cleanup)(mod);

        /* Module unload stuff */
        module_unload_free(mod);

        /* Free any allocated parameters. */
        ((void (*)(const struct kernel_param*, unsigned))SM_destroy_params)(mod->kp, mod->num_kp);

        /* Now we can delete it from the lists */
        mutex_lock(&module_mutex);
        /* Unlink carefully: kallsyms could be walking list. */
        list_del_rcu(&mod->list);
        /* Remove this module from bug list, this uses list_del_rcu */
        ((void (*)(struct module*))SM_module_bug_cleanup)(mod);
        /* Wait for RCU synchronizing before releasing mod->list and buglist. */
//        synchronize_rcu();
        ((typeof(&synchronize_sched))SM_synchronize_sched)();
        mutex_unlock(&module_mutex);

        /* This may be NULL, but that's OK */
        unset_module_init_ro_nx(mod);
//        ((void (*) (struct module*))SM_module_arch_freeing_init)(mod);
        vfree(mod->module_init);
//        module_memfree(mod->module_init);
        ((void (*)(const void*))SM_kfree)(mod->args);
//        percpu_modfree(mod);
        ((typeof(&free_percpu))SM_free_percpu)(mod->percpu);

        /* Free lock-classes; relies on the preceding sync_rcu(). */
        lockdep_free_key_range(mod->module_core, mod->core_size);

        /* Finally, free the core (containing the module structure) */
        unset_module_core_ro_nx(mod);
        vfree(mod->module_core);
//        module_memfree(mod->module_core);

#ifdef CONFIG_MPU
        update_protections(current->mm);
#endif
}

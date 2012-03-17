#include <stdlib.h>
#include <stdio.h>
#include <string.h>


typedef enum
{
    TASK_UNDEFINED  = 0,
    TASK_IN         = 1,
    TASK_OUT        = 2,
    TASK_PRINT      = 3,
    TASK_DELETE     = 4
} task_t;

typedef enum
{
    DIR_UNDEFINED   = 0,
    DIR_IN          = 1,
    DIR_OUT         = 2
} direction_t;

typedef enum
{
    ACT_UNDEFINED   = 0,
    ACT_BLOCK       = 1,
    ACT_UNBLOCK     = 2
} action_t;

typedef struct rule_s
{
    direction_t direction;
    action_t    action;
    char*       proto;
    char*       srcip;
    char*       srcnetmask;
    int         srcport;
    char*       destip;
    char*       destnetmask;
    int         destport;
} rule_t;


void print_instruction()
{
    printf("Linux Mini Firewall (CS5231)\n");
    printf("Edwin Boaz Soenaryo\n");
    printf("\n");
    printf("Usage:\n");
    printf("minifirewall [action] [options]\n");
    printf("\n");
    printf("Actions:\n");
    printf("  --in            : Create a new rule for inbound traffic\n");
    printf("  --out           : Create a new rule for outbound traffic\n");
    printf("  --print         : Print all current configuration records\n");
    printf("  --delete N      : Delete configuration record no. N\n");
    printf("\n");
    printf("Options for new rules:\n");
    printf("  --action N      : Block=1, Unblock=2     (required)\n");
    printf("  --srcip N       : Source IP address\n");
    printf("  --srcnetmask N  : Source IP net mask\n");
    printf("  --srcport N     : Source port number\n");
    printf("  --destip N      : Destination IP address\n");
    printf("  --destnetmask N : Destination IP address\n");
    printf("  --destport N    : Destination IP address\n");
}

void create_new_rule(rule_t *p_rule)
{
    printf("New rule:\n");
    printf("  direction   : %d\n", p_rule->direction);
    printf("  action      : %d\n", p_rule->action);
    printf("  protocol    : %s\n", p_rule->proto);
    printf("  srcip       : %s\n", p_rule->srcip);
    printf("  srcnetmask  : %s\n", p_rule->srcnetmask);
    printf("  srcport     : %d\n", p_rule->srcport);
    printf("  destip      : %s\n", p_rule->destip);
    printf("  destnetmask : %s\n", p_rule->destnetmask);
    printf("  destport    : %d\n", p_rule->destport); 
}

void print_rules()
{
    printf("Print rules\n");
}

void delete_rule(int id)
{
    printf("Delete rule %d\n", id);
}

#define ASSERT_SET_ONCE(var, val)                   \
    if (var && var != val)  goto arg_exception;     \
    var = val;

int main(int argc, char** argv)
{
    task_t task = TASK_UNDEFINED;
    rule_t rule;
    int i = 1, rule_to_delete = 0;
    
    if (argc < 2)
        goto arg_exception;
    
    memset(&rule, 0, sizeof(rule));
    
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--in") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_IN);
            ASSERT_SET_ONCE(rule.direction, DIR_IN);
        }
        else if (strcmp(argv[i], "--out") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_OUT);
            ASSERT_SET_ONCE(rule.direction, DIR_OUT);
        }
        else if (strcmp(argv[i], "--print") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_PRINT);
        }   
        else if (strcmp(argv[i], "--delete") == 0)
        {
            ASSERT_SET_ONCE(task, TASK_DELETE);
            ASSERT_SET_ONCE(rule_to_delete, atoi(DEREF_S(argv, ++i)));
        }
        else if (strcmp(argv[i], "--action") == 0)
        {
            ASSERT_SET_ONCE(rule.action, (action_t) atoi(argv[++i]));
        }
        else if (strcmp(argv[i], "--proto") == 0)
        {
            ASSERT_SET_ONCE(rule.proto, argv[++i]);
        }
        else if (strcmp(argv[i], "--srcip") == 0)
        {
            ASSERT_SET_ONCE(rule.srcip, argv[++i]);
        }
        else if (strcmp(argv[i], "--srcnetmask") == 0)
        {
            ASSERT_SET_ONCE(rule.srcnetmask, argv[++i]);
        }
        else if (strcmp(argv[i], "--srcport") == 0)
        {
            ASSERT_SET_ONCE(rule.srcport, atoi(argv[++i]));
        }
        else if (strcmp(argv[i], "--destip") == 0)
        {
            ASSERT_SET_ONCE(rule.destip, argv[++i]);
        }
        else if (strcmp(argv[i], "--destnetmask") == 0)
        {
            ASSERT_SET_ONCE(rule.destnetmask, argv[++i]);
        }
        else if (strcmp(argv[i], "--destport") == 0)
        {
            ASSERT_SET_ONCE(rule.destport, atoi(argv[++i]));
        }
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

    return 0;
    
arg_exception:
    print_instruction();
    return -1;
}

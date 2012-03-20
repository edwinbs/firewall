/**
 * minifirewall.c
 *
 * Configuration utility for the mini firewall kernel obejct.
 * This utility simply passes the command line arguments to the kernel.
 * Parsing is done by the kernel.
 *
 * \author  Edwin Boaz Soenaryo (A0082245J)
 * \email   edwinbs@comp.nus.edu.sg
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define PROC_FNAME  "/proc/minifirewall"
#define BUF_LEN     4096

void send_kernel_msg(const char* msg)
{
    int fd = 0;
    char resp_buf[BUF_LEN] = { 0 };
    
    fd = open(PROC_FNAME, O_WRONLY);
    
    if (!fd)
    {
        printf("Unable to communicate with minifirewall kernel object.\n");
        return;
    }
    
    write(fd, msg, strlen(msg));
    close(fd);
    
    fd = open(PROC_FNAME, O_RDONLY);
    read(fd, resp_buf, BUF_LEN-1);
    close(fd);
    
    printf("%s\n", resp_buf);
}

int main(int argc, char** argv)
{
    int i = 0;
    char cmd_str[BUF_LEN] = { 0 };
    
    for (i = 1; i < argc; i++)
    {
        strcat(cmd_str, argv[i]);
        strcat(cmd_str, " ");
    }
    
    send_kernel_msg(cmd_str);
    return 0;
}

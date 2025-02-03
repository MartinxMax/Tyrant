#ifndef RANDOM_MD5_H
#define RANDOM_MD5_H

#include <stdio.h>
#include <stdbool.h>

#define MD5_LENGTH 32

char* generate_random_md5(void);
bool is_valid_md5(const char *str);
char* get_file_hash(const char *file_path);

#endif // RANDOM_MD5_H

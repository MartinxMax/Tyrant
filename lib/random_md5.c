#include "random_md5.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * Generates a random MD5 hash by creating a random byte sequence and hashing it.
 * @return A static string containing the 32-character MD5 hash.
 */
char* generate_random_md5() {
    static char md5_str[MD5_LENGTH + 1];
    unsigned char random_str[16 + 1];

    if (!RAND_bytes(random_str, 16)) {
        fprintf(stderr, "Failed to generate random bytes\n");
        return NULL;
    }

    unsigned char md5_hash[EVP_MD_size(EVP_md5())];
    EVP_MD_CTX *md5_context = EVP_MD_CTX_new();
    if (!md5_context) {
        fprintf(stderr, "Failed to create MD5 context\n");
        return NULL;
    }

    if (EVP_DigestInit_ex(md5_context, EVP_md5(), NULL) != 1 ||
        EVP_DigestUpdate(md5_context, random_str, 16) != 1 ||
        EVP_DigestFinal_ex(md5_context, md5_hash, NULL) != 1) {
        fprintf(stderr, "Failed to compute MD5\n");
        EVP_MD_CTX_free(md5_context);
        return NULL;
    }

    EVP_MD_CTX_free(md5_context);

    for (int i = 0; i < EVP_MD_size(EVP_md5()); i++) {
        snprintf(&md5_str[i * 2], 3, "%02x", md5_hash[i]);
    }
    md5_str[MD5_LENGTH] = '\0';

    return md5_str;
}

/**
 * Checks whether the provided string is a valid MD5 hash (32 hex characters).
 * @param str The string to check.
 * @return true if the string is a valid MD5 hash, false otherwise.
 */
bool is_valid_md5(const char *str) {
    if (strlen(str) != MD5_LENGTH) {
        return false;
    }
    for (int i = 0; i < MD5_LENGTH; i++) {
        if (!((str[i] >= '0' && str[i] <= '9') || (str[i] >= 'a' && str[i] <= 'f') || (str[i] >= 'A' && str[i] <= 'F'))) {
            return false;
        }
    }
    return true;
}

/**
 * Computes the MD5 hash of a file.
 * @param file_path The path of the file to hash.
 * @return A static string containing the 32-character MD5 hash.
 */
char* get_file_hash(const char *file_path) {
    // 删除 static，改为动态分配内存
    char* md5_str = malloc(MD5_LENGTH + 1);  // 动态分配内存
    if (md5_str == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    unsigned char md5_hash[EVP_MD_size(EVP_md5())];

    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("fopen");
        free(md5_str);  // 释放分配的内存
        return NULL;
    }

    EVP_MD_CTX *md5_context = EVP_MD_CTX_new();
    if (!md5_context) {
        fclose(file);
        fprintf(stderr, "Failed to create MD5 context\n");
        free(md5_str);  // 释放分配的内存
        return NULL;
    }

    if (EVP_DigestInit_ex(md5_context, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(md5_context);
        fclose(file);
        fprintf(stderr, "Failed to initialize MD5 context\n");
        free(md5_str);  // 释放分配的内存
        return NULL;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(md5_context, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(md5_context);
            fclose(file);
            fprintf(stderr, "Failed to update MD5 hash\n");
            free(md5_str);  // 释放分配的内存
            return NULL;
        }
    }

    if (EVP_DigestFinal_ex(md5_context, md5_hash, NULL) != 1) {
        EVP_MD_CTX_free(md5_context);
        fclose(file);
        fprintf(stderr, "Failed to finalize MD5 hash\n");
        free(md5_str);  // 释放分配的内存
        return NULL;
    }

    EVP_MD_CTX_free(md5_context);
    fclose(file);

    for (int i = 0; i < EVP_MD_size(EVP_md5()); i++) {
        snprintf(&md5_str[i * 2], 3, "%02x", md5_hash[i]);
    }
    md5_str[MD5_LENGTH] = '\0';

    return md5_str;
}
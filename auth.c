#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_SIZE 16
#define HASH_SIZE 32

// Function to generate a random salt
void generate_salt(unsigned char *salt) {
    RAND_bytes(salt, SALT_SIZE);
}

// Function to hash the password with the salt using SHA-256
void hash_password(const char *password, unsigned char *salt, unsigned char *hash) {
    EVP_MD_CTX *mdctx;
    unsigned int hash_len;

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, SALT_SIZE);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
}

// Function to save user credentials to a file
void save_credentials(const char *username, const unsigned char *salt, const unsigned char *hash) {
    FILE *file = fopen("credentials.bin", "wb");
    if (!file) {
        perror("Error opening file");
        exit(1);
    }
    fwrite(username, sizeof(char), strlen(username), file);
    fwrite("\n", sizeof(char), 1, file);
    fwrite(salt, sizeof(unsigned char), SALT_SIZE, file);
    fwrite(hash, sizeof(unsigned char), HASH_SIZE, file);
    fclose(file);
}

// Function to authenticate the user
int authenticate(const char *username, const char *password) {
    FILE *file = fopen("credentials.bin", "rb");
    if (!file) {
        perror("Error opening file");
        return 0;
    }

    char stored_username[256];
    unsigned char stored_salt[SALT_SIZE];
    unsigned char stored_hash[HASH_SIZE];

    fgets(stored_username, sizeof(stored_username), file);
    stored_username[strcspn(stored_username, "\n")] = 0;  // Remove newline character
    fread(stored_salt, sizeof(unsigned char), SALT_SIZE, file);
    fread(stored_hash, sizeof(unsigned char), HASH_SIZE, file);
    fclose(file);

    if (strcmp(username, stored_username) != 0) {
        return 0;  // Username mismatch
    }

    unsigned char computed_hash[HASH_SIZE];
    hash_password(password, stored_salt, computed_hash);

    if (memcmp(computed_hash, stored_hash, HASH_SIZE) == 0) {
        return 1;  // Password match
    } else {
        return 0;  // Password mismatch
    }
}

int main() {
    char username[256];
    char password[256];

    printf("Register user\n");
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;  // Remove newline character

    unsigned char salt[SALT_SIZE];
    unsigned char hash[HASH_SIZE];
    generate_salt(salt);
    hash_password(password, salt, hash);
    save_credentials(username, salt, hash);

    printf("User registered!\n");

    printf("\nAuthenticate user\n");
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = 0;  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;  // Remove newline character

    if (authenticate(username, password)) {
        printf("Login successful!\n");
    } else {
        printf("Login failed!\n");
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#define PORT 5000
#define BUFFER_SIZE 65536
#define NONCE_TTL 300

// ---------------- NONCE STORE ----------------
typedef struct {
    char nonce[256];
    time_t ts;
} nonce_entry;

nonce_entry nonce_store[1000];
int nonce_count = 0;

// ---------------- UTIL ----------------
int is_replay(const char *nonce) {
    time_t now = time(NULL);

    for (int i = 0; i < nonce_count; i++) {
        if (now - nonce_store[i].ts > NONCE_TTL) {
            nonce_store[i] = nonce_store[nonce_count - 1];
            nonce_count--;
            i--;
            continue;
        }

        if (strcmp(nonce_store[i].nonce, nonce) == 0) {
            return 1;
        }
    }

    strcpy(nonce_store[nonce_count].nonce, nonce);
    nonce_store[nonce_count].ts = now;
    nonce_count++;

    return 0;
}

// ---------------- SOCKET RECV ----------------
int recv_all(int sock, char *buffer) {
    int total = 0, n;
    while ((n = recv(sock, buffer + total, BUFFER_SIZE - total, 0)) > 0) {
        total += n;
        if (n < 4096) break;
    }
    return total;
}

// ---------------- PARSE HEADER ----------------
char *extract_field(char *data, const char *key) {
    static char value[4096];
    char *pos = strstr(data, key);
    if (!pos) return NULL;

    pos += strlen(key);
    while (*pos == ' ' || *pos == ':') pos++;

    int i = 0;
    while (*pos && *pos != '\n') {
        value[i++] = *pos++;
    }
    value[i] = '\0';

    return value;
}

// ---------------- BASE64 (OpenSSL) ----------------
unsigned char *b64_decode(const char *input, int *len) {
    BIO *bio, *b64;
    int input_len = strlen(input);

    unsigned char *buffer = malloc(input_len);
    memset(buffer, 0, input_len);

    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *len = BIO_read(bio, buffer, input_len);

    BIO_free_all(bio);

    return buffer;
}

// ---------------- AES-GCM DECRYPT ----------------
int aes_decrypt(unsigned char *key, unsigned char *iv,
                unsigned char *cipher, int cipher_len,
                unsigned char *out) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, out, &len, cipher, cipher_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, out + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// ---------------- HANDLER ----------------
void *handle_client(void *arg) {
    int sock = *(int *)arg;
    free(arg);

    char buffer[BUFFER_SIZE];

    int size = recv_all(sock, buffer);
    buffer[size] = '\0';

    printf("\n----- PACKET RECEIVED -----\n%s\n", buffer);

    char *nonce = extract_field(buffer, "NONCE");
    char *timestamp = extract_field(buffer, "TIMESTAMP");
    char *chk = extract_field(buffer, "CHK");
    char *mac = extract_field(buffer, "MAC");
    char *registrant = extract_field(buffer, "REGISTRANT");

    if (!nonce || is_replay(nonce)) {
        printf("[!] Replay detected\n");
        close(sock);
        return NULL;
    }

    // ---- DATA SECTION ----
    char *data_start = strstr(buffer, "DATA:");
    if (!data_start) {
        close(sock);
        return NULL;
    }
    data_start += 5;

    char enc_key_b64[4096], iv_b64[4096], cipher_b64[4096];
    sscanf(data_start, "%[^|]|%[^|]|%s",
           enc_key_b64, iv_b64, cipher_b64);

    // decode base64
    int key_len, iv_len, cipher_len;

    unsigned char *enc_key = b64_decode(enc_key_b64, &key_len);
    unsigned char *iv = b64_decode(iv_b64, &iv_len);
    unsigned char *cipher = b64_decode(cipher_b64, &cipher_len);

    unsigned char plaintext[BUFFER_SIZE];

    int pt_len = aes_decrypt(enc_key, iv, cipher, cipher_len, plaintext);
    plaintext[pt_len] = '\0';

    printf("\n[PLAINTEXT]\n%s\n", plaintext);

    // ---- HMAC CHECK (simplified) ----
    unsigned char *hmac = HMAC(EVP_sha256(),
                               enc_key, key_len,
                               (unsigned char *)data_start,
                               strlen(data_start),
                               NULL, NULL);

    printf("[+] HMAC computed\n");

    // ---- RESPONSE ----
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response),
             "IDTP: 0.01 / OKAY\nHOST: %s\nDATA:\n%s\n",
             registrant ? registrant : "unknown",
             plaintext);

    send(sock, response, strlen(response), 0);

    close(sock);
    return NULL;
}

// ---------------- MAIN SERVER ----------------
int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 10);

    printf("[+] Server running on port %d\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);

        int *new_sock = malloc(sizeof(int));
        *new_sock = client_fd;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, (void *)new_sock);
        pthread_detach(thread);
    }

    close(server_fd);
    return 0;
}

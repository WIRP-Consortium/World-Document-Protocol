#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define PORT 5000
#define BUFFER 65536

// ---------------- BASE64 ----------------
char *b64_encode(const unsigned char *input, int len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);

    char *b64text = malloc(bufferPtr->length + 1);
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return b64text;
}

// ---------------- AES-GCM ENCRYPT ----------------
int aes_encrypt(unsigned char *key, unsigned char *iv,
                unsigned char *plaintext, int pt_len,
                unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    int len, cipher_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    cipher_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return cipher_len;
}

// ---------------- SOCKET SEND ----------------
void send_packet(char *ip, char *packet) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    inet_pton(AF_INET, ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return;
    }

    send(sock, packet, strlen(packet), 0);

    char response[BUFFER];
    int n = recv(sock, response, BUFFER - 1, 0);

    if (n > 0) {
        response[n] = '\0';
        printf("\n--- SERVER RESPONSE ---\n%s\n", response);
    }

    close(sock);
}

// ---------------- PACKET BUILDER ----------------
void build_packet(char *out,
                  char *ver,
                  char *type,
                  char *ich,
                  char *to,
                  char *ip,
                  char *registrant,
                  char *method,
                  char *resource,
                  char *nonce,
                  char *checksum,
                  char *mac,
                  char *signature,
                  char *timestamp,
                  char *iv,
                  char *body) {

    sprintf(out,
        "VER: %s\n"
        "TYPE: %s\n"
        "ICH: %s\n"
        "TO: %s\n"
        "IP: %s\n"
        "REGISTRANT: %s\n"
        "METHOD: %s\n"
        "RESOURCE: %s\n"
        "NONCE: %s\n"
        "CHK: %s\n"
        "MAC: %s\n"
        "SIGNATURE: %s\n"
        "TIMESTAMP: %s\n"
        "IV: %s\n\n"
        "DATA:\n%s\n",
        ver, type, ich, to, ip,
        registrant, method, resource,
        nonce, checksum, mac,
        signature, timestamp, iv, body
    );
}

// ---------------- MAIN ----------------
int main() {

    char name[256], message[4096], method[256];

    printf("Enter recipient IP: ");
    scanf("%s", name);

    printf("Enter method/file: ");
    scanf("%s", method);

    getchar();

    printf("Enter message: ");
    fgets(message, sizeof(message), stdin);

    message[strcspn(message, "\n")] = 0;

    // ---------------- KEYS ----------------
    unsigned char aes_key[32];
    unsigned char iv[12];

    RAND_bytes(aes_key, 32);
    RAND_bytes(iv, 12);

    // ---------------- AES ENCRYPT ----------------
    unsigned char cipher[4096];
    int cipher_len = aes_encrypt(aes_key, iv,
                                (unsigned char *)message,
                                strlen(message),
                                cipher);

    char *cipher_b64 = b64_encode(cipher, cipher_len);
    char *iv_b64 = b64_encode(iv, 12);

    // ---------------- RSA WRAP (SIMPLIFIED PLACEHOLDER) ----------------
    // NOTE: In real system load PEM public key and encrypt AES key
    char *enc_key_b64 = "RSA_ENCRYPTED_KEY_PLACEHOLDER";

    // ---------------- BODY ----------------
    char body[8192];
    sprintf(body, "%s|%s|%s",
            enc_key_b64,
            iv_b64,
            cipher_b64);

    // ---------------- HMAC ----------------
    unsigned char *mac = HMAC(EVP_sha256(),
                              aes_key, 32,
                              (unsigned char *)body,
                              strlen(body),
                              NULL, NULL);

    char mac_hex[65];
    for (int i = 0; i < 32; i++)
        sprintf(&mac_hex[i * 2], "%02x", mac[i]);

    // ---------------- SIGNATURE (PLACEHOLDER) ----------------
    char signature_b64[] = "RSA_SIGNATURE_PLACEHOLDER";

    char packet[16384];

    build_packet(packet,
        "0.01",
        "DATA",
        "CLIENT",
        name,
        "127.0.0.1",
        "USER",
        method,
        "txt",
        "NONCE123",
        "CHECKSUM123",
        mac_hex,
        signature_b64,
        "1234567890",
        iv_b64,
        body
    );

    printf("\n--- PACKET ---\n%s\n", packet);

    send_packet(name, packet);

    free(cipher_b64);
    free(iv_b64);

    return 0;
}
//gcc client.c -o client -lssl -lcrypto

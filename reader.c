/*
 * Copyright (C) 2026 Rohith Poyyara & WIRP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

int main() {
    FILE *file;

    uint8_t protocol;
    uint8_t name_len;
    uint8_t extended_len;

    unsigned char record_id[16];
    unsigned char public_key[128];
    unsigned char signature[128];

    char registry_name[256];
    char extended[256];

    uint64_t timestamp;
    uint64_t expiry;

    file = fopen("data/chain.dat", "rb");

    if (file == NULL) {
        printf("File not found\n");
        return 1;
    }

    int entry = 1;

    while (fread(&protocol, 1, 1, file) == 1) {

        fread(record_id, 1, 16, file);

        fread(&name_len, 1, 1, file);
        fread(registry_name, 1, name_len, file);
        registry_name[name_len] = '\0';

        fread(&extended_len, 1, 1, file);
        fread(extended, 1, extended_len, file);
        extended[extended_len] = '\0';

        fread(&timestamp, 8, 1, file);
        fread(&expiry, 8, 1, file);

        fread(public_key, 1, 128, file);
        fread(signature, 1, 128, file);

        printf("\n--- Entry %d ---\n", entry++);

        printf("Protocol: %d\n", protocol);
        printf("Registry Name: %s\n", registry_name);
        printf("Extended: %s\n", extended);
        printf("Timestamp: %llu\n", timestamp);
        printf("Expiry: %llu\n", expiry);

        long now = time(NULL);

        if (now > expiry) {
            printf("Status: EXPIRED\n");
        } else {
            printf("Status: ACTIVE\n");
        }

        printf("Record ID: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", record_id[i]);

        printf("\nPublic Key: ");
        for (int i = 0; i < 32; i++)
            printf("%02x", public_key[i]);

        printf("\nSignature: ");
        for (int i = 0; i < 32; i++)
            printf("%02x", signature[i]);

        printf("\n-----------------\n");
    }

    fclose(file);
    return 0;
}

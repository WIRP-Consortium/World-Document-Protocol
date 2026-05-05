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

    uint32_t timestamp;   // FIXED (was 64-bit wrong)
    time_t now;

    file = fopen("data/chain.dat", "rb");

    if (file == NULL) {
        printf("File not found\n");
        return 1;
    }

    int entry = 1;

    while (1) {

        if (fread(&protocol, 1, 1, file) != 1)
            break;

        if (fread(record_id, 1, 16, file) != 16)
            break;

        if (fread(&name_len, 1, 1, file) != 1)
            break;

        if (name_len >= 255) break;

        if (fread(registry_name, 1, name_len, file) != name_len)
            break;
        registry_name[name_len] = '\0';

        if (fread(&extended_len, 1, 1, file) != 1)
            break;

        if (extended_len >= 255) break;

        if (fread(extended, 1, extended_len, file) != extended_len)
            break;
        extended[extended_len] = '\0';

        if (fread(&timestamp, 4, 1, file) != 1)   // FIXED 4 bytes
            break;

        if (fread(public_key, 1, 128, file) != 128)
            break;

        if (fread(signature, 1, 128, file) != 128)
            break;

        printf("\n--- Entry %d ---\n", entry++);

        printf("Protocol: %d\n", protocol);
        printf("Registry Name: %s\n", registry_name);
        printf("Extended: %s\n", extended);
        printf("Timestamp: %u\n", timestamp);

        now = time(NULL);

        printf("Status: %s\n", (now > timestamp) ? "EXPIRED" : "ACTIVE");

        printf("Record ID: ");
        for (int i = 0; i < 16; i++)
            printf("%02x", record_id[i]);

        printf("\nPublic Key: ");
        for (int i = 0; i < 128; i++)
            printf("%02x", public_key[i]);

        printf("\nSignature: ");
        for (int i = 0; i < 128; i++)
            printf("%02x", signature[i]);

        printf("\n-----------------\n");
    }

    fclose(file);
    return 0;
}

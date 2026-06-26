# Specification of Internet Data Transmission Protocol (IDTP)

## IDTP Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 101 | NO CHECKSUM | Missing CHK header |
| 103 | NO MAC | Missing MAC header |
| 104 | EXPIRED PACKET | Timestamp outside 300 second window |
| 105 | NO NONCE | Missing replay protection nonce |
| 107 | INVALID PACKET | DATA format error |
| 111 | REPLAY ATTACK DETECTED | Duplicate nonce detected |
| 115 | NO PRIVATE KEY | User key not found |
| 121 | INVALID CHECKSUM | HMAC-SHA256 mismatch |
| 122 | INVALID MAC | MAC validation failed |
| 126 | DECRYPTION FAILED | TCP reset during communication |
| 127 | SOCKET ERROR | Socket failure |
| 129 | DECRYPTION ERROR | AES-GCM / RSA-OAEP failure |

---

# Error Details

## 101 - NO CHECKSUM

The received packet does not contain a checksum.

Required header:


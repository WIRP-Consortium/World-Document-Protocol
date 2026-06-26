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


---

## 104 - EXPIRED PACKET

The packet timestamp is outside the allowed time window.

Default timeout:


---

## 105 - NO NONCE

The packet does not contain a nonce.

Nonce is required for replay protection.

---

## 107 - INVALID PACKET

The DATA section format is invalid.

Expected format:


---

## 111 - REPLAY ATTACK DETECTED

A previously used nonce was received again.

The server rejects duplicate packets.

---

## 115 - NO PRIVATE KEY

The server cannot find the user's private key.

Possible causes:

- User not registered
- Key file missing
- Invalid identity

---

## 121 - INVALID CHECKSUM

Checksum verification failed.

Algorithm:


Possible causes:

- Modified packet
- Incorrect encryption key
- Corrupted data

---

## 122 - INVALID MAC

Message authentication failed.

The packet integrity cannot be verified.

---

## 126 - DECRYPTION FAILED

The TCP connection was closed or reset before completion.

---

## 127 - SOCKET ERROR

A network socket error occurred.

Possible causes:

- Connection failure
- Network interruption
- Invalid socket state

---

## 129 - DECRYPTION ERROR

Cryptographic decryption failed.

Algorithms:

Possible causes:

- Invalid encrypted data
- Wrong key
- Corrupted ciphertext

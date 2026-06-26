# Specification of Internet Data Transmission Protocol (IDTP)

## Packet Header Specification

IDTP packets are composed of header fields and a DATA payload.

---

## Header Fields

| Field | Name | Description |
|------|------|-------------|
| VER | Version | Protocol version identifier |
| TYPE | Type | Type of transmitted data or packet |
| ICH | Internet Cryptographic Hash | Cryptographic hash identifier |
| TO | Server IP | Destination server IP address |
| IP | Client IP | Source client IP address |
| REGISTRANT | Registrant Name | Identity of registered user/client |
| AGENT | Client Software | Client application identifier |
| METHOD | Method | Requested operation or resource path |
| RESOURCE | Resource | Requested file extension/type |
| NONCE | Nonce | Random value used for replay protection |
| CHK | Checksum | Packet integrity checksum |
| CLIENT_KEY | Client Public Key | Public key used for encryption |
| MAC | Message Authentication Code | HMAC authentication value |
| SIGNATURE | Signature | Digital signature for verification |
| TIMESTAMP | Time | Packet creation time |
| IV | Initialization Vector | AES encryption initialization vector |
| DATA | Payload Data | Encrypted or transmitted content |

---

# Field Details

## VER

Protocol version.

Example: Version 0.01


---

## TYPE

Packet type.

Examples: REQUEST, OKAY, ERROR


---

## ICH

Internet Cryptographic Hash.

Used to identify cryptographic data.

---

## TO

Destination server address.


---

## IP

Client network address.


---

## REGISTRANT

Registered client identity.

---

## AGENT

Client software information.


---

## METHOD

Requested resource or action.


---

## RESOURCE

Resource extension/type.


---

## NONCE

Random generated value.

Purpose:

- Replay attack protection
- Packet uniqueness

---

## CHK

Packet checksum.

Algorithm:


Used to verify packet integrity.

---

## CLIENT_KEY

Client public key.

Used for secure key exchange.

Format:


---

## MAC

Message Authentication Code.

Provides:

- Authentication
- Integrity verification

Algorithm:


---

## SIGNATURE

Digital signature of packet data.

Used to verify sender authenticity.

---

## TIMESTAMP

Packet creation time.


---

## IV

Initialization Vector.

Used by AES encryption.


---

## DATA

Packet payload.

Can contain:

- encrypted message
- file content
- response data

=========================================

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

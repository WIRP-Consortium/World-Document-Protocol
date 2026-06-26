##Specification of Internet Data Transmission Protocol

IDTP ERROR CODES
================

101  NO CHECKSUM
     Missing CHK header


103  NO MAC
     Missing MAC header


104  EXPIRED PACKET
     Timestamp outside 300 second window


105  NO NONCE
     Missing replay protection nonce


107  INVALID PACKET
     DATA format error


111  REPLAY ATTACK DECTECTED
     Duplicate nonce


115  NO PRIVATE KEY
     User key not found


121  INVALID CHECKSUM
     HMAC SHA256 mismatch


122  INVALID MAC
     MAC validation failed


129  DECRYPTION ERROR
     AES-GCM / RSA OAEP failure


126  DECRYPTION FAILED
     TCP reset during communication


127  SOCKET ERROR
     Socket failure


202  FILE NOT FOUND
     Requested resource missing

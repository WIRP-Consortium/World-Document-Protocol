import socket
import requests
import json
import os
import hashlib
import secrets
import sys
import subprocess
import webbrowser
import hmac
import base64
import codecs
import time

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from pathlib import Path
from PIL import Image
import io

PORT = 5000
VERSION = "0.01"
TYPE = "DATA"
PORT2 = 5001

#HOST = "0.0.0.0"
HOST = "127.0.0.1"

REGISTRY_FILE = os.path.join("data", "registry.dat")

with open("keys/private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# Get public IP
ipa = requests.get("https://api.ipify.org").text.strip()


def idtp_packet(ver, msg_type, ich, to, ip_addr,
                registrant, method, resource, nonce, checksum, public_key, mac, signature, timestamp, character, iv, data):
    return f"""VER: {ver}
TYPE: {msg_type}
ICH: {ich}
TO: {to}
IP: {ip_addr}
REGISTRANT: {registrant}
METHOD: {method}
RESOURCE: {resource}
NONCE: {nonce}
CHK: {checksum}
CHTR: {character}
PUBLIC_KEY: {public_key}
MAC: {mac}
SIGNATURE: {signature}
TIMESTAMP: {timestamp}
IV: {iv}

DATA:
{data}
"""

def aes_encrypt(key, iv, data):
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data.encode(), None)
    return base64.b64encode(ciphertext).decode()

def try_send(ip, packet):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)

            print(f"Connecting to {ip}:{PORT}...")
            peer.connect((ip, PORT))

            peer.sendall(packet.encode("utf-8"))

            print("Message sent successfully")

            response = peer.recv(8192).decode("utf-8", errors="ignore")

            print("\n--- SERVER RESPONSE ---\n")
            print(response)

            if response is None:
                print("ERROR, Section 104")

            for line in response.splitlines():
                if "RESOURCE:" in line:
                    ext = line.split("/")[-1].strip()

            lines = response.splitlines()
            size_line = [l for l in lines if l.startswith("DATA:")][0]
            data = int(size_line.split(":")[1].strip())
            
            if ext == "jpg":
                img = Image.open(io.BytesIO(data))
                img.show()
                print("Successfully extract jpg")
            else:
                print("Normal")
            
            return True

    except socket.timeout:
        print("Connection timed out")
        return False

    except ConnectionRefusedError:
        print("Connection refused")
        return False

    except Exception as e:
        print("Direct P2P failed")
        print("Reason:", e)
        return False


def find_user(name):
    if not os.path.exists(REGISTRY_FILE):
        print(f"Registry file not found: {REGISTRY_FILE}")
        return None

    try:
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if item.get("fullname") == name:
                    return item

    except Exception as e:
        print("Failed to read registry:", e)

    return None

def recv_all(conn):
    buffer = b""
    while True:
        part = conn.recv(4096)
        if not part:
            break
        buffer += part
        if len(part) < 4096:
            break
    return buffer

def main():
    while True:
        try:
            name = input("\nEnter recipient name: ").strip()
            method = input("\nEnter File Method: ").strip()

            if not name:
                print("Name cannot be empty")
                continue

            if method == "/":
                method = "/"

            ext = Path(method).suffix.lstrip(".")

            if name.lower() in ("exit", "quit"):
                print("Exiting...")
                break

            msg = input("\nEnter message: ").strip()

            if not msg:
                print("Message cannot be empty")
                continue

            result_data = find_user(name)

            if not result_data:
                print("User not found")
                continue

            aes_key = os.urandom(32)
            iv = os.urandom(12)

            encrypted_msg = aes_encrypt(aes_key, iv, msg)

            # ---------------- RSA KEY WRAP ----------------
            public_key_txt = result_data.get("public_key", "UNKNOWN")
            public_key_txt = public_key_txt.replace("\\n", "\n").strip()

            public_key = serialization.load_pem_public_key(
                public_key_txt.encode("utf-8")
            )

            enc_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            enc_aes_key_b64 = base64.b64encode(enc_aes_key).decode()

            registered_name = result_data.get("fullname")
            ich = result_data.get("ich", "UNKNOWN")
            public_key_txt = result_data.get("public_key", "UNKNOWN")
            #destination_ip = result_data.get("ip")
            destination_ip = "192.168.1.8"

            timestamp = time.time()

            #nonce = hashlib.sha256(secrets.token_bytes(128)).hexdigest()[:32]
            nonce = secrets.token_hex(16)

            body = enc_aes_key_b64 + "|" + base64.b64encode(iv).decode() + "|" + encrypted_msg

            checksum = hmac.new(aes_key, body.encode(), hashlib.sha256).hexdigest()

            dat = nonce + destination_ip + ich + encrypted_msg
            mac = hmac.new(aes_key, dat.encode(), hashlib.sha256).hexdigest()
            count = len(body)

            data_to_sign = nonce + "|" + str(timestamp) + "|" + body

            signature = private_key.sign(
                data_to_sign.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            signature_b64 = base64.b64encode(signature).decode()

            if not destination_ip:
                print("User has no registered IP")
                continue

            packet = idtp_packet(
                ver=VERSION,
                msg_type=TYPE,
                ich=ich,
                to=destination_ip,
                ip_addr=ipa,
                registrant=registered_name,
                method=method,
                resource=ext,
                nonce=nonce,
                checksum=checksum,
                public_key=enc_aes_key_b64,
                mac=mac,
                signature=signature_b64,
                timestamp=str(int(timestamp)),
                character=str(count),
                iv=base64.b64encode(iv).decode(),
                data=body
            )

            success = try_send(destination_ip, packet)

            if success:
                print("Delivery attempt completed")
            else:
                print("Delivery failed")

        except KeyboardInterrupt:
            print("\nExiting...")
            break


if __name__ == "__main__":
    main()

import socket
import threading
import os
import json
import base64
import hashlib
import hmac
import time
import ssl

from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path

HOST = "0.0.0.0"
PORT = 443
VERSION = "0.01"
TYPE = "RETURN"

DATA_DIR = "data"
INDEX_DIR = os.path.join(DATA_DIR, "indexes")

AGENT = "WIRP idtpd Version 0.01"

nonce_store = {}
NONCE_TTL = 300

print(AGENT)
print("Internet Data Transmission Protocol(IDTP) 0.01")
print("WIRP IDTP Daemon 0.01")

def try_send(ip, packet):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)

            print(f"Connecting to {ip}:{PORT}...")
            peer.connect((ip, PORT))

            peer.sendall(packet.encode("utf-8"))

            print("Message sent successfully")
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

def load_all_data():
    results = []

    if not os.path.exists(INDEX_DIR):
        return results

    for file in os.listdir(INDEX_DIR):
        if file.endswith(".dat"):
            file_path = os.path.join(INDEX_DIR, file)

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                results.append({
                    "fullname": data.get("fullname"),
                    "folder": data.get("folder"),
                    "primary_file": data.get("primary_file"),
                    "private_key": data.get("asymmetric_private"),
                    "public_key": data.get("asymmetric_public")
                })

            except Exception as e:
                print(f"Failed reading {file}: {e}")

    return results

def is_replay(nonce):
    now = time.time()

    expired = [n for n, t in nonce_store.items() if now - t > NONCE_TTL]
    for n in expired:
        del nonce_store[n]

    if nonce in nonce_store:
        return True

    nonce_store[nonce] = now
    return False

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

def get_publickey(registrant):
    if not registrant:
        return None
    
    data_copy = load_all_data()

    for thing in data_copy:
        if thing.get("fullname", "").strip() == registrant.strip():
            return thing.get("public_key")
        
    return None

def get_folder(registrant):
    if not registrant:
        return None
    
    data_cpy = load_all_data()

    for hap in data_cpy:
        if hap.get("fullname", "").strip() == registrant.strip():
            return hap.get("folder")
        
    return None

def get_file(registrant):
    if not registrant:
        return None
    
    data_2 = load_all_data()

    for fil in data_2:
        if fil.get("fullname", "").strip() == registrant.strip():
            return fil.get("primary_file")
        
    return None

def get_key_by_registrant(registrant):
    if not registrant:
        return None

    data_list = load_all_data()

    for item in data_list:
        if item.get("fullname", "").strip() == registrant.strip():
            return item.get("private_key")

    return None

def idtp_packet(ver, msg_type, to, ip_addr,
                registrant, method, nonce, checksum, public_key, client_key, mac, timestamp, character, iv, data):
    return f"""VER: {ver}
TYPE: {msg_type}
TO: {to}
IP: {ip_addr}
REGISTRANT: {registrant}
METHOD: {method}
NONCE: {nonce}
CHK: {checksum}
CHTR: {character}
PUBLIC_KEY: {public_key}
CLIENT_KEY: {client_key}
MAC: {mac}
TIMESTAMP: {timestamp}
IV: {iv}

DATA:
{data}
"""

def send_error(conn, code, message):
    error_packet = f"""IDTP: {VERSION} / ERROR
CODE: {code}
MESSAGE: {message}
TIMESTAMP: {int(time.time())}
"""

    conn.sendall(error_packet.encode("utf-8"))

def parse_idtp(packet: str):
    header = {}
    data_lines = []
    in_data = False
    in_public_key = False
    in_check = False
    time_stamp = False
    in_client_key = False
    registrant = None

    for line in packet.splitlines():
        line = line.rstrip()

        if line == "PUBLIC_KEY:":
            in_public_key = True
            header["PUBLIC_KEY"] = ""
            continue

        if in_public_key:
            if line == "DATA:":
                in_public_key = False
                in_data = True
                continue
            header["PUBLIC_KEY"] += line + "\n"
            continue

        if line == "CHK:":
            in_check = True
            header["CHK"] = ""
            continue

        if in_check:
            if line == "":
                continue
            header["CHK"] = line.strip()
            in_check = False
            continue

        if line == "TIMESTAMP:":
            time_stamp = True
            header["TIMESTAMP"] = ""
            continue

        if time_stamp:
            if line == "":
                continue
            header["TIMESTAMP"] = line.strip()
            time_stamp = False
            continue

        if line == "CLIENT_KEY:":
            in_client_key = True
            header["CLIENT_KEY"] = ""
            continue


        if in_client_key:
            if line.startswith("MAC:"):
                in_client_key = False
                header["MAC"] = line.split(":", 1)[1].strip()
                continue

            header["CLIENT_KEY"] += line + "\n"
            continue

        if line == "DATA:":
            in_data = True
            continue

        if in_data:
            data_lines.append(line)
            continue

        if line.startswith("REGISTRANT:"):
            header["REGISTRANT"] = line.split(":", 1)[1].strip()
            continue

        if ": " in line:
            key, value = line.split(": ", 1)
            header[key.strip()] = value.strip()

    data = "\n".join(data_lines).strip()
    return header, data


def aes_decrypt(key, iv, data):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, data, None)


def handle_client(conn, addr):
    print(f"\n[+] Connected: {addr}")

    try:
        data = recv_all(conn)

        if data:
            idtp = data.decode("utf-8", errors="ignore")

            print("\n----- MESSAGE RECEIVED -----")
            print(idtp)

            header, body = parse_idtp(idtp)

            current_time = int(time.time())

            if "SIGNATURE" not in header:
                print("NO SIGNATURE")
                return
            
            registrant = header.get("REGISTRANT", "").strip()
            public_key = get_publickey(registrant)
            folder = get_folder(registrant)
            file_path = get_file(registrant)

            ich = header.get("ICH")
            destination_ip = header.get("TO")
            chk_value = header.get("CHK")
            mac = header.get("MAC")
            nonce = header.get("NONCE")
            method = header.get("METHOD")
            resource = header.get("RESOURCE")
            client_ip = header.get("IP")
            signature = base64.b64decode(header["SIGNATURE"])
            timestamp = int(float(header["TIMESTAMP"]))
            client_key_pem = header.get("CLIENT_KEY")

            client_key = serialization.load_pem_public_key(
                client_key_pem.encode("utf-8")
            )
            
            date = datetime.fromtimestamp(timestamp, tz=timezone.utc)

            data_to_sign = nonce + "|" + str(timestamp) + "|" + body

            if not chk_value:
                print("[!]NO CHECKSUM")
                send_error(conn, 101, "NO CHECKSUM")
                return
            
            if not mac:
                print("[!]NO MAC")
                send_error(conn, 103, "NO MAC")
                return
            
            if current_time - timestamp > 300:
                print("[!]PACKET EXPIRED")
                send_error(conn, 104, "EXPIRED PACKET")
                return
            
            if not nonce:
                send_error(conn, 105, "NO NONCE")
                return

            if is_replay(nonce):
                print("[!] REPLAY ATTACK DETECTED")
                send_error(conn, 111, "REPLAY ATTACK DECTECTED")
                return
            
            print(f"CHECKSUM: {chk_value}")
            print(f"TIME: {date}")
            print(f"ich: {ich}")
            print(f"ip: {destination_ip}")
            print(f"FOLDER: {folder}")

            registrant = header.get("REGISTRANT", "").strip()

            private_key = get_key_by_registrant(registrant)

            if not private_key:
                print("[!] PRIVATE KEY NOT FOUND")
                print("Registrant:", repr(registrant))
                send_error(conn, 115, "NO PRIVATE KEY")
                return

            try:
                private_key = private_key.replace("\\n", "\n")

                private_key_obj = serialization.load_pem_private_key(
                    private_key.encode("utf-8"),
                    password=None
                )
                parts = body.split("|")
                if len(parts) != 3:
                    print("[!] Invalid packet format")
                    send_error(conn, 107, "INVALID PACKET")
                    return

                enc_key_b64, iv_b64, ciphertext_b64 = parts

                aes_key = private_key_obj.decrypt(
                    base64.b64decode(enc_key_b64),
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                iv = base64.b64decode(iv_b64)
                ciphertext = base64.b64decode(ciphertext_b64)

                plaintext = aes_decrypt(aes_key, iv, ciphertext)

                calculated_chk = hmac.new(
                    aes_key,
                    body.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                dat = nonce + destination_ip + ich + ciphertext_b64
                calculated_mac = hmac.new(
                    aes_key,
                    dat.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                if calculated_chk != chk_value:
                    send_error(conn, 121, "INVALID CHECKSUM")
                    return
                
                if method == "/":
                    route = rf"{folder}\{file_path}"
                    forres = Path(file_path).suffix.lstrip(".")
                else:
                    route = rf"{folder}\{method}"
                    forres = Path(method).suffix.lstrip(".")

                response_type = "ERROR" if not Path(route).exists() else "OKAY"

                if response_type == "ERROR":
                    send_error(conn, 202, "FILE NOT FOUND")
                    return
                
                if resource == "jpg":
                    with open(route, "rb") as s:
                        content = base64.b64encode(s.read()).decode()
                elif resource == "png":
                    with open(route, "rb") as s:
                        content = base64.b64encode(s.read()).decode()
                elif resource == "txt":
                    with open(route, "r", encoding="utf-8") as s:
                        content = s.read()
                elif resource == "smrl":
                    with open(route, "r", encoding="utf-8") as s:
                        content = s.read()
                else:
                    with open(route, "r", encoding="utf-8") as s:
                        content = s.read()
                
                print(f"FOLDER PATH: {route}")
                
                if calculated_mac != mac:
                    print("[!]INVALID MAC")
                    send_error(conn, 122, "INVALID MAC")
                    return
                else:
                    print("[+]VALID MAC")

                print("\n-------Header---------\n")
                for k, v in header.items():
                    print(f"{k}: {v}")

                print("\n----- DATA -----")
                print(plaintext.decode("utf-8", errors="ignore"))
                print("Registrant:", registrant)
          
                response_key = os.urandom(32)
                response_iv = os.urandom(12)

                idtp_return = f"""IDTP: {VERSION} / {response_type}
HOST: {registrant}
RESOURCE: {route} / {forres}
TYPE: {forres}
DATA:
{content}
                """
                aes = AESGCM(response_key)

                encrypted_response = aes.encrypt(
                    response_iv,
                    idtp_return.encode(),
                    None
                )

                encrypted_key = client_key.encrypt(
                    response_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                packet = (
                    base64.b64encode(encrypted_key).decode()
                    + "|"
                    + base64.b64encode(response_iv).decode()
                    + "|"
                    + base64.b64encode(encrypted_response).decode()
                )

                conn.sendall(packet.encode())
            except Exception as e:
                print("[!] Decryption error:", e)
                send_error(conn, 129, "DECRYPTION ERROR")

    except ConnectionResetError:
        print(f"[!] Client closed connection: {addr}")
        send_error(conn, 126, "DECRYPTION FAILED")

    except OSError as e:
        print(f"[!] Socket error: {e}")
        send_error(conn, 127, "SOCKET ERROR")

    finally:
        conn.close()
        print(f"[-] Disconnected: {addr}")
        


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(10)

    print(f"[+] Listening on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True
            )

            thread.start()

    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")

    finally:
        server.close()


if __name__ == "__main__":
    main()

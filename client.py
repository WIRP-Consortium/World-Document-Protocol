# Project Name
# Copyright (C) 2026 Rohith Poyyara & WIRP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
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
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QMainWindow,
    QLineEdit, QPushButton, QVBoxLayout
)
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QTextEdit

PORT = 5000
VERSION = "0.01"
TYPE = "DATA"

HOST = "0.0.0.0"

REGISTRY_FILE = os.path.join("data", "registry.dat")

with open("keys/private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

#public IP
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

def parse_response(response):
    data = {}

    header, _, body = response.partition("\n\n")

    for line in header.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()

    # save payload
    data["DATA"] = body.strip()

    return data

def try_send(ip, packet):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as peer:
            peer.settimeout(5)

            peer.connect((ip, PORT))

            peer.sendall(packet.encode("utf-8"))

            raw = peer.recv(8192)

            if not raw:
                return False

            response = raw.decode("utf-8", errors="ignore")

            parsed = parse_response(response)

            print("TYPE:", parsed.get("TYPE"))
            print("RESOURCE:", parsed.get("RESOURCE"))
            print("DATA:", parsed.get("DATA"))

            return parsed

    except socket.timeout:
        print("Connection timed out (server did not reply)")
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

def main(name, msg, method):
    try:

        if method == "/":
            method = "/"

        ext = Path(method).suffix.lstrip(".")

        if not msg:
            print("Message cannot be empty")
            return

        result_data = find_user(name)

        if not result_data:
            print("User not found")
            return

        aes_key = os.urandom(32)
        iv = os.urandom(12)

        encrypted_msg = aes_encrypt(aes_key, iv, msg)

            #RSA KEY WRAP
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
        destination_ip = "#"

        timestamp = time.time()
      
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
            return

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

        response = try_send(destination_ip, packet)

        if response:
            print("Delivery attempt completed")
        else:
            print("Delivery failed")

        return response

    except KeyboardInterrupt:
        print("\nExiting...")
        return

class EditApp(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Client")
        self.resize(1280, 720)

        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(15)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        label = QLabel("Recipient:")
        mesg = QLabel("Enter message:")
        fl_method = QLabel("Enter File Method")

        self.recipient = QLineEdit()
        self.msg = QLineEdit()
        self.method = QLineEdit()

        send_button = QPushButton("Send")

        layout.addWidget(label)
        layout.addWidget(self.recipient)

        layout.addWidget(mesg)
        layout.addWidget(self.msg)

        layout.addWidget(fl_method)
        layout.addWidget(self.method)
        
        layout.addWidget(send_button)
        send_button.clicked.connect(self.send)

        layout.addWidget(self.output)

        central.setLayout(layout)

    def send(self):
        name = self.recipient.text().strip()
        msg = self.msg.text().strip()
        method = self.method.text().strip()

        response = main(name, msg, method)

        if response:
            self.output.clear()   # remove old data
            self.output.setText(response.get("DATA", "No data"))

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = EditApp()
    window.show()

    sys.exit(app.exec())

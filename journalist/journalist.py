import os
import random
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from dotenv import load_dotenv
import requests


load_dotenv()
tor_url = os.getenv('TOR_URL')

# route traffic through tor network
proxies = {
    'http': 'socks5h://localhost:9050',
    'https': 'socks5h://localhost:9050'
}


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem, private_pem


def generate_nickname():
    words = [
        "falcon", "lion", "eagle", "shadow", "fox", "wolf",
        "panther", "cobra", "hawk", "raven", "tiger", "viper"
    ]
    word = random.choice(words)
    number = random.randint(1000, 9999)
    return f"{word}{number}"


def store_keys_in_db(nickname, public_key, private_key):
    conn = sqlite3.connect('journalist.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS journalist_keys (
            nickname TEXT PRIMARY KEY,
            public_key TEXT,
            private_key TEXT
        )
    ''')
    c.execute('''
        INSERT OR REPLACE INTO journalist_keys (nickname, public_key, private_key)
        VALUES (?, ?, ?)
    ''', (nickname, public_key, private_key))
    conn.commit()
    conn.close()


def send_public_key_to_server(public_key_pem, nickname):
    url = tor_url + '/register_public_key'
    data = {
        'nickname': nickname,
        'public_key': public_key_pem.decode('utf-8')
    }

    try:
        response = requests.post(url, data=data, proxies=proxies)

        if response.status_code == 200:
            print(
                f"Successfully registered public key with nickname {nickname}")
        else:
            print(
                f"Failed to register public key with the server. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")


def decrypt_aes_key(encrypted_aes_key, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'), password=None)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def decrypt_file(encrypted_file, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_file) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    unpadded_data = unpadder.update(padded_data) + unpadder.finalize()

    return unpadded_data


def retrieve_file_and_decrypt(nickname):
    conn = sqlite3.connect('journalist.db')
    c = conn.cursor()
    c.execute(
        'SELECT private_key FROM journalist_keys WHERE nickname = ?', (nickname,))
    result = c.fetchone()
    conn.close()

    if result is None:
        print("Nickname not found in local database.")
        return

    private_key_pem = result[0]

    response = requests.get(f'{tor_url}/retrieve_file/{nickname}', proxies=proxies)
    if response.status_code != 200:
        print("Failed to retrieve file from server.")
        return

    data = response.json()
    encrypted_file = bytes.fromhex(data['encrypted_file'])
    encrypted_aes_key = bytes.fromhex(data['encrypted_aes_key'])
    iv = bytes.fromhex(data['iv'])

    aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)
    decrypted_file = decrypt_file(encrypted_file, aes_key, iv)

    output_filename = f"{nickname}_decrypted_output"
    with open(output_filename, 'wb') as f:
        f.write(decrypted_file)

    print(f"Decrypted file saved as {output_filename}")


def main():

    print("1. Generate and register new RSA key pair")
    print("2. Retrieve and decrypt file using nickname")
    choice = input("Choose an option: ")

    if choice == "1":
        public_key, private_key = generate_rsa_key_pair()
        nickname = generate_nickname()
        store_keys_in_db(nickname, public_key.decode(
            'utf-8'), private_key.decode('utf-8'))
        send_public_key_to_server(public_key, nickname)

    elif choice == "2":
        nickname = input("Enter nickname: ")
        retrieve_file_and_decrypt(nickname)

    else:
        print("Invalid choice.")


if __name__ == '__main__':
    main()

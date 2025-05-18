from dotenv import load_dotenv
from flask import Flask, request, jsonify
import os
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.padding import PKCS7

app = Flask(__name__)

@app.route('/hello', methods=['GET'])
def hello():
    return "Hello from WhistleDrop"


def init_db():
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS public_keys (
            nickname TEXT PRIMARY KEY,
            public_key TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            nickname TEXT PRIMARY KEY,
            encrypted_aes_key TEXT,
            iv TEXT,
            encrypted_file BLOB
        )
    ''')
    conn.commit()
    conn.close()


def get_most_recent_nickname():
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute('SELECT nickname FROM public_keys ORDER BY rowid DESC LIMIT 1')
    result = c.fetchone()
    conn.close()

    if result is None:
        return None
    return result[0]


def get_public_key(nickname):
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute('SELECT public_key FROM public_keys WHERE nickname = ?', (nickname,))
    result = c.fetchone()
    conn.close()

    if result is None:
        return None
    public_key_pem = result[0].encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key


@app.route('/register_public_key', methods=['POST'])
def register_public_key():
    nickname = request.form['nickname']
    public_key_pem = request.form['public_key']

    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO public_keys (nickname, public_key)
        VALUES (?, ?)
    ''', (nickname, public_key_pem))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Public key registered successfully'}), 200


@app.route('/upload', methods=['POST'])
def upload_file():
    nickname = get_most_recent_nickname()
    if not nickname:
        return jsonify({'error': 'No nickname found for the journalist'}), 400

    file = request.files['file']
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    file_content = file.read()

    padder = PKCS7(128).padder()  # 128 bits = 16 bytes block size
    padded_data = padder.update(file_content) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_file = encryptor.update(padded_data) + encryptor.finalize()

    public_key = get_public_key(nickname)
    if public_key is None:
        return jsonify({'error': 'Public key not found for this nickname'}), 400

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO files (nickname, encrypted_aes_key, iv, encrypted_file)
        VALUES (?, ?, ?, ?)
    ''', (nickname, encrypted_aes_key.hex(), iv.hex(), sqlite3.Binary(encrypted_file)))

    c.execute('DELETE FROM public_keys WHERE nickname = ?', (nickname,))

    conn.commit()
    conn.close()

    response = {
        'nickname': nickname,
        'encrypted_aes_key': encrypted_aes_key.hex(),
        'iv': iv.hex(),
    }
    return jsonify(response), 200


@app.route('/retrieve_file/<nickname>', methods=['GET'])
def retrieve_file(nickname):
    conn = sqlite3.connect('server.db')
    c = conn.cursor()
    c.execute(
        'SELECT encrypted_file, encrypted_aes_key, iv FROM files WHERE nickname = ?', (nickname,))
    result = c.fetchone()
    conn.close()

    if result is None:
        return jsonify({'error': 'File not found'}), 404

    encrypted_file = result[0]
    encrypted_aes_key_hex = result[1]
    iv_hex = result[2]

    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
    iv = bytes.fromhex(iv_hex)

    response = {
        'encrypted_file': encrypted_file.hex(),
        'encrypted_aes_key': encrypted_aes_key.hex(),
        'iv': iv.hex(),
    }
    return jsonify(response), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=8080)

import os
from dotenv import load_dotenv
import requests
import socks
import socket

load_dotenv()
tor_url = os.getenv("TOR_URL")

# route traffic through tor network
proxies = {
    'http': 'socks5h://localhost:9050',
    'https': 'socks5h://localhost:9050'
}

def upload_file(file_path):
    url = tor_url + '/upload'
    with open(file_path, 'rb') as file:
        files = {'file': file}

        response = requests.post(tor_url, files=files, proxies=proxies)

    if response.status_code == 200:
        data = response.json()
        print(f"File uploaded successfully. Nickname: {data['nickname']}")
        print(f"Encrypted AES Key: {data['encrypted_aes_key']}")
        print(f"Nickname: {data['nickname']}")
    else:
        print('Failed to upload file.')
        print(response.text)

if __name__ == '__main__':
    file_path = input("Enter the path to the file to upload: ")
    upload_file(file_path)

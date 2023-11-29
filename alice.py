import socket
from Crypto.PublicKey import RSA
import hashlib 
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

#Create keys for encrypting, decrypting, and signing
def generate_keys():
    modulus_length = 2048

    key = RSA.generate(modulus_length)
    alice_public = key.public_key().export_key("PEM")
    alice_private = key.export_key("PEM")

    return alice_public, alice_private

#Read from each of the 5 files, hashes them, and combines them into a final message.
#Add each hash to the dictionary, alice_hashes
def read_from_file(alice_hashes):
    final_message = ""
    for i in range(1, 6):
        file_name = "alice_files/file" + str(i) + ".txt"
        file = open(file_name, "r")
        content = file.read()
        result = hashlib.sha256(content.encode())
        final_message = final_message + "-----BEGIN MESSAGE-----\n" + result.hexdigest() + "\n-----END MESSAGE-----\n"
        alice_hashes[result.hexdigest()] = i
    return final_message
    
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

alice_public, alice_private = generate_keys()
session_key = get_random_bytes(16)
alice_hashes = {}

#Connect to bob using sockets
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        while True:
            
            #This is the public key from bob, which we assume alice receives it without being tampered with
            bob_public = conn.recv(4096).decode()

            conn.sendall(alice_public)
            
            final_message = read_from_file(alice_hashes)
            
            bob_pub_key = RSA.import_key(bob_public)
            cipher_rsa = PKCS1_OAEP.new(bob_pub_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)
            conn.sendall(encrypted_session_key)
            
            #This is the message from bob with the hash values 
            data = conn.recv(4096)
            
            nonce = data.split(b"-----BEGIN NONCE-----\n")
            nonce = b''.join(nonce)
            nonce = nonce.split(b"\n-----END NONCE-----\n")
            data = nonce
            nonce = nonce[0]
            
            data.pop(0)
            data = b''.join(data)
            tag = data.split(b"-----BEGIN TAG-----\n")
            tag = b''.join(tag)
            tag = tag.split(b"\n-----END TAG-----\n")
            data = tag
            tag = tag[0]
            
            data.pop(0)
            data = b''.join(data)
            ciphertext = data.split(b"-----BEGIN CIPHER-----\n")
            ciphertext = b''.join(ciphertext)
            ciphertext = ciphertext.split(b"\n-----END CIPHER-----\n")
            ciphertext = ciphertext[0]
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            hashes = cipher_aes.decrypt_and_verify(ciphertext, tag)
            
            #Split the message into 5 separate parts
            hashes = hashes.split(b"-----BEGIN MESSAGE-----\n")
            hashes = b''.join(hashes)
            hashes = hashes.split(b"\n-----END MESSAGE-----\n")
            
            #Check if any of the hashes are the same
            for hash in hashes:
                if hash.decode() in alice_hashes:
                    print("file" + str(alice_hashes[hash.decode()]) + ".txt is the same as one of Bob's files")
            exit(0)
            

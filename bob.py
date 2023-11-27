import socket
from Crypto.PublicKey import RSA
import hashlib 


#Create keys for encrypting, decrypting, and signing
def generate_keys():
    modulus_length = 2048

    key = RSA.generate(modulus_length)
    #print (key.exportKey())

    pub_key = key.publickey()
    #print (pub_key.exportKey())

    return key, pub_key

#Read from each of the 5 files, hashes them, and combines them into a final message.
#Add each hash to the dictionary, bob_hashes
def read_from_file(bob_hashes):
    final_message = ""
    for i in range(1, 6):
        file_name = "bob_files/file" + str(i) + ".txt"
        file = open(file_name, "r")
        content = file.read()
        result = hashlib.sha256(content.encode())
        final_message = final_message + "-----BEGIN MESSAGE-----\n" + result.hexdigest() + "\n-----END MESSAGE-----"
        bob_hashes[result.hexdigest()] = i
    return final_message

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
bob_hashes = {}

#Connect to alice using sockets
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    final_message = read_from_file(bob_hashes)
    s.sendall(bytes(final_message, "utf-8"))
    data = s.recv(4096)
    #Split the message into 5 separate parts
    hashes = data.split(b"-----BEGIN MESSAGE-----\n")
    hashes = b''.join(hashes)
    hashes = hashes.split(b"\n-----END MESSAGE-----")
            
    #Check if any of the hashes are the same
    for hash in hashes:
        if hash.decode() in bob_hashes:
            print("file" + str(bob_hashes[hash.decode()]) + ".txt is the same as one of Bob's files")
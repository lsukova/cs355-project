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
#Add each hash to the dictionary, alice_hashes
def read_from_file(alice_hashes):
    final_message = ""
    for i in range(1, 6):
        file_name = "alice_files/file" + str(i) + ".txt"
        file = open(file_name, "r")
        content = file.read()
        result = hashlib.sha256(content.encode())
        final_message = final_message + "-----BEGIN MESSAGE-----\n" + result.hexdigest() + "\n-----END MESSAGE-----"
        alice_hashes[result.hexdigest()] = i
    return final_message
    
HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

private, public = generate_keys()
alice_hashes = {}

#Connect to bob using sockets
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        while True:
            
            #This is the message from bob with the hash values and signatures
            #TODO: Implement encryption, decryption, and signing
            data = conn.recv(4096)
            if not data:
                break
            final_message = read_from_file(alice_hashes)
            conn.sendall(bytes(final_message, "utf-8"))
            
            #Split the message into 5 separate parts
            hashes = data.split(b"-----BEGIN MESSAGE-----\n")
            hashes = b''.join(hashes)
            hashes = hashes.split(b"\n-----END MESSAGE-----")
            
            #Check if any of the hashes are the same
            for hash in hashes:
                if hash.decode() in alice_hashes:
                    print("file" + str(alice_hashes[hash.decode()]) + ".txt is the same as one of Bob's files")
            exit(0)
            

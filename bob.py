import socket
from Crypto.PublicKey import RSA
import hashlib 
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


#Create keys for encrypting, decrypting, and signing
def generate_keys():
    modulus_length = 2048

    key = RSA.generate(modulus_length)
    bob_public = key.public_key().export_key("PEM")
    bob_private = key.export_key("PEM")

    return bob_public, bob_private

#Read from each of the 5 files, hashes them, and combines them into a final message.
#Add each hash to the dictionary, bob_hashes
def read_from_file(bob_hashes):
    final_message = ""
    for i in range(1, 6):
        file_name = "bob_files/file" + str(i) + ".txt"
        file = open(file_name, "r")
        content = file.read()
        result = hashlib.sha256(content.encode())
        final_message = final_message + "-----BEGIN MESSAGE-----\n" + result.hexdigest() + "\n-----END MESSAGE-----\n"
        bob_hashes[result.hexdigest()] = i
    return final_message

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server
bob_hashes = {}

bob_public, bob_private = generate_keys()

#Connect to alice using sockets
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(bob_public)
    
    final_message = read_from_file(bob_hashes)
    
    #Sign the message and add it to the final_message
    priv_key = RSA.import_key(bob_private)
    hashed_msg = SHA256.new(bytes(final_message, "utf-8"))
    signature = pkcs1_15.new(priv_key).sign(hashed_msg)       
            
    final_message = "-----BEGIN SIGNATURE-----\n" + signature.decode("latin-1") + "\n-----END SIGNATURE-----\n" + final_message
    s.sendall(bytes(final_message, "utf-8"))
    
    alice_public = s.recv(4096)
    s.sendall(bytes(final_message, "utf-8"))
    data = s.recv(4096)
    
    #Parse the signature from Alice
    alice_signature = data.split(b"\n-----END SIGNATURE-----\n")
    alice_signature = alice_signature[0].split(b"-----BEGIN SIGNATURE-----\n")
    alice_signature = alice_signature[1].decode()
    hashes = data.split(b"\n-----END SIGNATURE-----\n")
    hashes = hashes[1].decode()
    
    #Verify the signature and exit if not verified
    alice_pub_key = RSA.import_key(alice_public)
    hashed_msg = SHA256.new(bytes(hashes, "utf-8"))
    try:
        pkcs1_15.new(alice_pub_key).verify(hashed_msg, bytes(alice_signature, "latin-1"))
        print("The signature is valid.")
    except Exception as e:
        print ("The signature is not valid.")
        exit(1)
    
    #Split the message into 5 separate parts
    hashes = hashes.split("-----BEGIN MESSAGE-----\n")
    hashes = ''.join(hashes)
    hashes = hashes.split("\n-----END MESSAGE-----\n")
            
    #Check if any of the hashes are the same
    for hash in hashes:
        if hash in bob_hashes:
            print("file" + str(bob_hashes[hash]) + ".txt is the same as one of Alices's files")
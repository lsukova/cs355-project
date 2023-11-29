import socket
from Crypto.PublicKey import RSA
import hashlib 
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

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
            
            #This is the message from bob with the hash values and signatures
            data = conn.recv(4096)
            
             #Parse the signature from Alice
            bob_signature = data.split(b"\n-----END SIGNATURE-----\n")
            bob_signature = bob_signature[0].split(b"-----BEGIN SIGNATURE-----\n")
            bob_signature = bob_signature[1].decode()
            hashes = data.split(b"\n-----END SIGNATURE-----\n")
            hashes = hashes[1].decode()
    
            #Verify the signature and exit if not verified
            bob_pub_key = RSA.import_key(bob_public)
            hashed_msg = SHA256.new(bytes(hashes, "utf-8"))
            try:
              pkcs1_15.new(bob_pub_key).verify(hashed_msg, bytes(bob_signature, "latin-1"))
              print("The signature is valid.")
            except Exception as e:
              print ("The signature is not valid.")
              exit(1)
            
            final_message = read_from_file(alice_hashes)
            
            #Sign the message and add it to the final_message
            priv_key = RSA.import_key(alice_private)
            hashed_msg = SHA256.new(bytes(final_message, "utf-8"))
            signature = pkcs1_15.new(priv_key).sign(hashed_msg)       
            final_message = "-----BEGIN SIGNATURE-----\n" + signature.decode("latin-1") + "\n-----END SIGNATURE-----\n" + final_message
            conn.sendall(bytes(final_message, "utf-8"))
            
            #Split the message into 5 separate parts
            hashes = hashes.split("-----BEGIN MESSAGE-----\n")
            hashes = ''.join(hashes)
            hashes = hashes.split("\n-----END MESSAGE-----\n")
            
            #Check if any of the hashes are the same
            for hash in hashes:
                if hash in alice_hashes:
                    print("file" + str(alice_hashes[hash]) + ".txt is the same as one of Bob's files")
            exit(0)
            

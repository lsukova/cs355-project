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

#Return the nonce, tag, and ciphertext from the data sent by Alice
def parse_data(data):
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
    
    return nonce, tag, ciphertext

#Encrypt the message data, add headings, and return the entire message,
#which will be sent to Alice
def encrypt_msg(final_message, session_key):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(final_message.encode("utf-8"))
    nonce = cipher_aes.nonce
    encrypted_msg = "-----BEGIN NONCE-----\n" + nonce.decode("latin-1") + "\n-----END NONCE-----\n"
    encrypted_msg = encrypted_msg + "-----BEGIN TAG-----\n" + tag.decode("latin-1") + "\n-----END TAG-----\n"
    encrypted_msg = encrypted_msg + "-----BEGIN CIPHER-----\n" + ciphertext.decode("latin-1") + "\n-----END CIPHER-----\n"
    
    return encrypted_msg

#Return the encrypted session key and signature from the message from Alice
def parse_key_and_signature(encrypted_session_key):
    signature = encrypted_session_key.split(b"-----BEGIN SIGNATURE-----\n")
    signature = b''.join(signature)
    signature = signature.split(b"\n-----END SIGNATURE-----\n")
    encrypted_session_key = signature[1]
    signature = signature[0]

    encrypted_session_key = encrypted_session_key.split(b"-----BEGIN SESSION_KEY-----\n")
    encrypted_session_key = b''.join(encrypted_session_key)
    encrypted_session_key = encrypted_session_key.split(b"\n-----END SESSION_KEY-----\n")
    encrypted_session_key = encrypted_session_key[0]
    
    return encrypted_session_key, signature


#Parse the hashes and check each hash to see if it is the same as any of Bob's
def check_for_similiar_files(hashes, bob_hashes):
    #Split the message into 5 separate part
    hashes = hashes.split(b"-----BEGIN MESSAGE-----\n")
    hashes = b''.join(hashes)
    hashes = hashes.split(b"\n-----END MESSAGE-----\n")
            
    #Check if any of the hashes are the same
    for hash in hashes:
        if hash.decode() in bob_hashes:
            print("file" + str(bob_hashes[hash.decode()]) + ".txt is the same as one of Alices's files")

def main():
    #Use HOST and PORT to connect to Alice
    HOST = "127.0.0.1" 
    PORT = 65432
    bob_hashes = {}
    bob_public, bob_private = generate_keys()
    priv_key = RSA.import_key(bob_private)

    #Connect to Alice using sockets
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.connect((HOST, PORT))
        conn.sendall(bob_public)
        alice_public = conn.recv(4096)
        alice_pub_key = RSA.import_key(alice_public)
        
        #Receive the encrypted session key from Alice
        encrypted_session_key = conn.recv(4096)
        encrypted_session_key, signature = parse_key_and_signature(encrypted_session_key)
        
        #Check to see if the signature given is correct
        try:
            sig_hash = SHA256.new(encrypted_session_key)
            pkcs1_15.new(alice_pub_key).verify(sig_hash, signature)
            print ("The signature is valid.")
        except (ValueError, TypeError):
            print ("The signature is not valid.")
            exit(1)
        
        #Decrypt the session key    
        cipher_rsa = PKCS1_OAEP.new(priv_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        
        #Get the hashes of the text files
        final_message = read_from_file(bob_hashes)

        #Encrypt hte message with the session key
        encrypted_msg = encrypt_msg(final_message, session_key)
        conn.sendall(bytes(encrypted_msg, "latin_1"))
        
        #Receive the encrypted hashes from Alice
        data = conn.recv(4096)
                
        #Get hte nonce, tag, and ciphertext from the message
        nonce, tag, ciphertext = parse_data(data)
        
        #Decrypt the data and check the tags to see if the data was tampered with
        try:
            #Uncomment one of these to test tampering
            #ciphertext = b"a" + ciphertext[1:]
            #tag = get_random_bytes(16)
            
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            hashes = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except (ValueError):
            print("Tampering Detected")
            exit(1)
        
        #See if Alice and Bob have any similar files
        check_for_similiar_files(hashes, bob_hashes)
        exit(0)

if __name__ == '__main__':
    main()

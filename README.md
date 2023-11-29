# CS 355-project
## Language Used
-Python
## Libraries Used
- PyCryptodome
- Hashlib
- Socket
## Security Analysis
Our goal was to make sure that an adversary could not tamper with any of the files through transport without the receiver knowing. We also wanted to make sure that an adversary could not gather any information about the plaintext from any of the ciphertexts. Since we used plaintext headers to help us format the messages, we are only counting the encrypted information, not these headers. Finally, we wanted to make sure that neither Alice nor Bob could gain any information about the other person's code segments, while still checking if they had the same code segments or not.

For our implementation, we first assumed that Bob and Alice shared their public keys with each other in person or through a trusted certificate authority. This way neither of the public keys can be tampered with. So, when the public keys get transferred through the sockets, in reality, they would be handing each other the keys or getting them from the CA.

After they receive the public keys, Alice generates a random 16-byte key that will be used to communicate with Bob throughout the session. Alice encrypts the session key with Bob's public key using PyCryptodomes algorithm based on RSA and OAEP padding. Then Alice runs the key through the hashing function SHA256. This hash then goes through PyCryptodomes pkcs1_15 RSA signing function to give us Alice's digital signature. The signature is prepended to the encrypted session key and sent to Bob. Bob verifies that the signature is indeed Alice's by verifying it with Alice's public key. If the verification is correct, then the communication continues. If not, then the communication is closed.

Next, Bob decrypts the session key using his own private key. Now Alice and Bob can use symmetric encryption to communicate. Then Bob loops through each 500 MB file and runs it through SHA256 to create a hash (Our implementation uses smaller files, but it should work for 500 MB files). Bob creates a dictionary to store the hash and the file number to use later. Each file hash is added to a message. Once all the file hashes have been added, the message is encrypted using AES. A MAC tag and a nonce are created as well. The ciphertext, the tag, and the nonce are all sent to Alice. Alice can use the MAC tag to verify that the data has not been tampered with, and she can also decrypt the data using the nonce and session key. Alice performs the same steps to send the information to Bob, and Bob performs the same steps to decrypt the data.

The communication between Alice and Bob is finished. Now, they can use the dictionary they created earlier to check if any of the hashes sent from the other party matches any of the hashes they have. If any hashes match, then they know that the other party has that same code segment. 

So, we achieved our first goal of preventing tampering through the use of digital signatures and MAC tags. We achieved our second goal of making sure no adversary could gain any information about the plaintexts by using secure symmetric and asymmetric encryption schemes. Finally, we achieved our third goal of making sure that Alice and Bob could not gain any information about the other person's code segments by hashing the code segments before sending them.

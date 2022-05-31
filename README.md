# RSA-Public-Key-Cryptography

Alice:
1. Gets her public and private keys from the provided file.
2. Gets Bob’s public key from the provided file.
3. Gets the plaintext from the file “Message.txt”.
4. Performs encryption on the message with Bob’s public key.
5. Signs the ciphertext with her private key.
6. Transmits the signature and ciphertext to Bob via ZeroMQ.

Bob:
1. Gets his public and private keys from the provided file.
2. Gets Alice’s public key from the provided file.
3. Receives the signature and ciphertext.
4. Checks the validity of signature by using the verification function and Alice’s public key.
5. If the signature was valid, he decrypts the ciphertext by his private key and obtains the plaintext

# Encryption-and-Decryption-of-a-file

This is an application to encrypt and decrypt any file implemented in Python 2.

In "gui_enc.py" file,

1) We browse for a file to be encrypted or decrypted say "file"
2) We generate a 256 bit(32 byte) key to be stored into a file named "key_file.txt" . 
3) We encrypt our browsed file using this 256 bit key and AES encryption technique .
4) Now , we encrypt the key in key_file.txt using RSA public key of X509 certificate as "enc_file"
5) So, now we have two encrypted files.
    i)  a file with encrypted key as "enc_key_file.txt"
    ii) encrypted file i.e., "enc_file"
6) Now, we send these two files in an open channel to receiver.

In "gui_dec.py" file, 

1) Now at the receiver end, we decrypt the "enc_file" using RSA certificate(which contains private key associated with previous public key we used to encrypt key).
2) So,We decrypt the key and acquire the key in plain text.
3) This extracted key is used to decrypt the "enc_file"  to get original file.  


Description 

f12.der contains public key to encrypt key in gui_enc.py's execution
f12.p12 contains private key to decrypt key in gui_dec.py's execution
You can use data.txt file to be encrypted and encrypted.

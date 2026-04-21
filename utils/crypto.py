from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import hashlib

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

def encrypt_file(data):
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    rsa = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa)
    enc_key = rsa_cipher.encrypt(aes_key)

    return ciphertext, cipher.nonce, tag, enc_key

def decrypt_file(ciphertext, nonce, tag, enc_key):
    rsa = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa)
    aes_key = rsa_cipher.decrypt(enc_key)

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def generate_hash(data):
    return hashlib.sha256(data).hexdigest()
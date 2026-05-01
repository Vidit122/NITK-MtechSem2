def split_blocks(data, block_size=8):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def des_encrypt_block(block, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(block)


def cfb_encrypt_manual(plaintext, key, iv):
    blocks = split_blocks(plaintext)
    ciphertext = b''
    prev = iv
    for block in blocks:
        keystream = des_encrypt_block(prev, key)
        c = xor_bytes(block, keystream)
        ciphertext += c
        prev = c
    return ciphertext


def cfb_decrypt_manual(ciphertext, key, iv):
    blocks = split_blocks(ciphertext)
    plaintext = b''
    prev = iv
    for block in blocks:
        keystream = des_encrypt_block(prev, key)
        p = xor_bytes(block, keystream)
        plaintext += p
        prev = block
    return plaintext


key = b'8bytekey'
iv  = get_random_bytes(8)
msg = b'Transfer=1000USDAftersometime'
print("Original message = ", msg)


ciphertext = cfb_encrypt_manual(msg, key, iv)
plaintext  = cfb_decrypt_manual(ciphertext, key, iv)


print("IV        :", iv.hex())
print("Ciphertext:", ciphertext.hex())
print("Plaintext :", plaintext)


print("Attack=======================================")
# ---- attacker ----
ciphertext = bytearray(ciphertext)
ciphertext[9] ^= ord('1') ^ ord('9')


# ---- receiver ----
decrypted = cfb_decrypt_manual(ciphertext, key, iv)
print("Tampered plaintext:", decrypted)

def split_blocks(data, block_size=8):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def des_encrypt_block(block, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(block)


def des_decrypt_block(block, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(block)


def int_to_bytes(n):
    return n.to_bytes(8, 'big')


def ctr_encrypt_manual(data, key, nonce):
    blocks = split_blocks(data)
    result = b''
    counter = 0
    for block in blocks:
        counter_block = xor_bytes(nonce, int_to_bytes(counter))
        keystream = des_encrypt_block(counter_block, key)
        result += xor_bytes(block, keystream)
        counter += 1
    return result


def ctr_decrypt_manual(data, key, nonce):
    blocks = split_blocks(data)
    result = b''
    counter = 0
    for block in blocks:
        counter_block = xor_bytes(nonce, int_to_bytes(counter))
        keystream = des_encrypt_block(counter_block, key)
        result += xor_bytes(block, keystream)
        counter += 1
    return result


key = b'8bytekey'
iv  = get_random_bytes(8)
msg = b'Pay=1000USD'

print("Original Message = ", msg)
ciphertext = ctr_encrypt_manual(msg, key, iv)
plaintext = ctr_decrypt_manual(ciphertext, key, iv)
print("IV        :", iv.hex())
print("Ciphertext:", ciphertext.hex())
print("Plaintext :", plaintext)



# -------- Attacker flips bits --------
ciphertext = bytearray(ciphertext)
ciphertext[4] ^= ord('1') ^ ord('9')

plaintext  = ctr_decrypt_manual(ciphertext, key, iv)
print("Tampered plaintext :", plaintext)

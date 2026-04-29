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


def cbc_encrypt_manual(plaintext, key, iv):
    plaintext = pad(plaintext, 8)
    blocks = split_blocks(plaintext)
    ciphertext = b''
    prev = iv
    for block in blocks:
        x = xor_bytes(block, prev)
        c = des_encrypt_block(x, key)
        ciphertext += c
        prev = c
    return ciphertext


def cbc_decrypt_manual(ciphertext, key, iv):
    blocks = split_blocks(ciphertext)
    plaintext = b''
    prev = iv
    for block in blocks:
        p = xor_bytes(des_decrypt_block(block, key), prev)
        plaintext += p
        prev = block
    return unpad(plaintext, 8)


key = b'8bytekey'
iv  = get_random_bytes(8)
msg = b'Secret meet at Palace'


ciphertext = cbc_encrypt_manual(msg, key, iv)
plaintext  = cbc_decrypt_manual(ciphertext, key, iv)


print("IV        :", iv.hex())
print("Ciphertext:", ciphertext.hex())
print("Plaintext :", plaintext)


# Weakness / Attacks
print("Attack======================================")
plaintext = b"userid=10;user=false;"
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, 8))
print("Original plaintext:", plaintext)




# --- Attacker side ---
ciphertext = bytearray(ciphertext)
ciphertext[8 + 0] ^= ord('f') ^ ord('t')
ciphertext[8 + 1] ^= ord('a') ^ ord('r')
ciphertext[8 + 2] ^= ord('l') ^ ord('u')
ciphertext[8 + 3] ^= ord('s') ^ ord('e')
ciphertext[8 + 4] ^= ord('e') ^ ord(' ')


# --- Victim decrypts ---
decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted = unpad(decipher.decrypt(ciphertext), 8)
print("Tampered plaintext:", decrypted)


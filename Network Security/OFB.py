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


def ofb_encrypt_manual(data, key, iv):
    blocks = split_blocks(data)  
    result = b''
    stream = iv
    for block in blocks:
        stream = des_encrypt_block(stream, key)
        result += xor_bytes(block, stream[:len(block)])
    return result


def ofb_decrypt_manual(data, key, iv):
    blocks = split_blocks(data)
    result = b''
    stream = iv
    for block in blocks:
        stream = des_encrypt_block(stream, key)
        result += xor_bytes(block, stream)
    return result


key = b'8bytekey'
iv  = get_random_bytes(8)
msg = b'Output Feedback Mode'


ciphertext = ofb_encrypt_manual(msg, key, iv)
plaintext  = ofb_decrypt_manual(ciphertext, key, iv)


print("IV        :", iv.hex())
print("Ciphertext:", ciphertext.hex())
print("Plaintext :", plaintext)


print("ATTACK-------------------------------")
ms1 = b'SLOW'
ms2 = b'HOPE'
ciphertext1 = ofb_encrypt_manual(ms1, key, iv)
ciphertext2 = ofb_encrypt_manual(ms2, key, iv)
print("Message1 - ", ms1)
print("Message2 - ", ms2)
print("Ciphertext1 - ", ciphertext1)
print("Ciphertext2 - ", ciphertext2)

recovered = bytes(a ^ b ^ c for a, b, c in zip(ciphertext1, ciphertext2, ms1))
print("Attacker tries to get the plaintext 2 by using Ciphertext1, Ciphertext2 and Plaintext1")
print(recovered)

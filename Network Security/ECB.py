from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def split_blocks(data, block_size=8):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]


def ecb_encrypt_manual(plaintext, key):
    plaintext = pad(plaintext, 8)
    blocks = split_blocks(plaintext, 8)
    ciphertext = b''
    for block in blocks:
        cipher = DES.new(key, DES.MODE_ECB)  
        ciphertext += cipher.encrypt(block)

    return ciphertext



def ecb_decrypt_manual(ciphertext, key):
    blocks = split_blocks(ciphertext, 8)
    plaintext = b''
    for block in blocks:
        cipher = DES.new(key, DES.MODE_ECB)
        plaintext += cipher.decrypt(block)

    return unpad(plaintext, 8)


key = b'8bytekey'

plaintext1 = b'ATTACKDOWN'
ciphertext1 = ecb_encrypt_manual(plaintext1, key)
message1 = ecb_decrypt_manual(ciphertext1, key)

plaintext2 = b'ATTACKUP'
ciphertext2 = ecb_encrypt_manual(plaintext2, key)
message2 = ecb_decrypt_manual(ciphertext2, key)

plaintext3 = b'ATTACKUP'
ciphertext3 = ecb_encrypt_manual(plaintext3, key)
message3 = ecb_decrypt_manual(ciphertext3, key)

print("Message = ", message1, "Ciphertext = ", ciphertext1.hex())
print("Message = ", message2, "Ciphertext = ", ciphertext2.hex())
print("Message = ", message3, "Ciphertext = ", ciphertext3.hex())





print("\nAttack ---------------------------------")
plaintext_attack = b'BLOCKONEBLOCKTWOBLOCKTHR'
ciphertext_attack = ecb_encrypt_manual(plaintext_attack, key)
print("\nOriginal Plaintext:", plaintext_attack)
print("Original Ciphertext:", ciphertext_attack.hex())
blocks = split_blocks(ciphertext_attack, 8)
print("\nCiphertext Blocks:")

for i, block in enumerate(blocks):
    print(f"Block {i+1}:", block.hex())

tampered_ciphertext = blocks[1] + blocks[0] + blocks[2] + blocks[3]
print("\nTampered Ciphertext:", tampered_ciphertext.hex())
tampered_message = ecb_decrypt_manual(tampered_ciphertext, key)
print("\nDecrypted Tampered Plaintext:", tampered_message)



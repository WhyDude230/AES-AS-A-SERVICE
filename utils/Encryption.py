from utils.AES import *


class AESEncryption(AES):
    def __init__(self):
        pass

    @staticmethod
    def xor(plain_block, key):
        return bytearray([i ^ j for i, j in zip(plain_block, key)])

    @staticmethod
    def breakMessage(message, len_of_block=16):
        list_of_blocks = [message[i:i+len_of_block]
                          for i in range(0, len(message), len_of_block)]
        return list_of_blocks

    def encrypt_ecb(self, data, key):
        block_size = len(key)
        padded_data = pad(data, block_size)
        num_blocks = len(padded_data)//block_size
        encrypted_data = b''

        for i in range(num_blocks):
            block = padded_data[i*block_size:(i+1)*block_size]
            encrypted_block = self.encrypt(block, key)
            encrypted_data += encrypted_block

        return encrypted_data

    def decrypt_ecb(self, data, key):
        block_size = len(key)
        num_blocks = len(data) // block_size
        decrypted_data = b''

        for i in range(num_blocks):
            block = data[i * block_size: (i + 1) * block_size]
            decrypted_block = self.decrypt(block, key)
            decrypted_data += decrypted_block

        return unpad(decrypted_data, block_size)

    def encrypt_cbc(self, plaintext, key, iv):
        plaintext = pad(plaintext, 16)
        print(plaintext)
        blocklist = AESEncryption.breakMessage(plaintext)
        list_of_ciphers = []
        for i in range(len(blocklist)):
            cipher = AESEncryption.xor(blocklist[i], iv)
            cipher = self.encrypt(cipher, key)
            print(cipher.hex())
            iv = cipher
            list_of_ciphers.append(cipher)
        return b"".join(list_of_ciphers)

    def decrypt_cbc(self, ciphertext, key, iv):
        list_of_cipher = AESEncryption.breakMessage(ciphertext)
        list_of_decrypted_blocks = []
        for i in range(len(list_of_cipher)):
            if i == 0:
                tmp = self.decrypt(list_of_cipher[i], key)
                plain = AESEncryption.xor(tmp, iv)
            else:
                tmp = self.decrypt(list_of_cipher[i], key)
                plain = AESEncryption.xor(tmp, list_of_cipher[i - 1])
            list_of_decrypted_blocks.append(plain)
        return unpad(b''.join(list_of_decrypted_blocks), 16)

    def encrypt_ctr(self, data, key, counter):
        encrypted_data = b""
        data = AESEncryption.breakMessage(data)
        for block in data:
            cipher = self.encrypt(counter, key)
            encrypted_block = AESEncryption.xor(cipher, block)
            encrypted_data += encrypted_block
            counter = AESEncryption._increment_counter(counter)
        return encrypted_data

    def decrypt_ctr(self, data, key, counter):
        decrypted_data = []
        data = AESEncryption.breakMessage(data)
        for block in data:
            plain = self.encrypt(counter, key)
            decrypted_block = AESEncryption.xor(plain, block)
            decrypted_data.append(decrypted_block)
            counter = AESEncryption._increment_counter(counter)

        return unpad(b''.join(decrypted_data), 16)

    @staticmethod
    def _increment_counter(counter):
        counter = int(counter.hex(), 16) + 1
        return bytes.fromhex(hex(counter)[2:])

    def Encrypt(self, mode, plaintext, key, iv=None):
        print("Encryption  ")
        if mode.upper() == "ECB":
            return AESEncryption.encrypt_ecb(self, plaintext, key)
        elif mode.upper() == "CBC":
            print(iv)
            if iv == bytes([0]):
                return "iv is not specified"
            return AESEncryption.encrypt_cbc(self, plaintext, key, iv)
        elif mode.upper() == "CTR":
            print(mode, iv.hex())
            if iv == bytes([0]):
                return "nonce is not specified"
            return AESEncryption.encrypt_ctr(self, plaintext, key, iv)
        else:
            return "Mode not found"

    def Decrypt(self, mode, ciphertext, key, iv=None):
        if mode.upper() == "ECB":
            return AESEncryption.decrypt_ecb(self, ciphertext, key)
        elif mode.upper() == "CBC":
            if iv == bytes([0]):
                return "iv is not specified"
            return AESEncryption.decrypt_cbc(self, ciphertext, key, iv)
        elif mode.upper() == "CTR":
            if iv == bytes([0]):
                return "nonce is not specified"
            return AESEncryption.decrypt_ctr(self, ciphertext, key, iv)
        else:
            return "Mode not found"


"""
key = bytes.fromhex("c0614198f86916ba49f5ba6cb717a979")
iv = bytes.fromhex("5f644d5f3f9016ada4d40d7ca0afa892")
plaintext = b"mahdi"

A = AESEncryption()

data = A.Encrypt("ctr", plaintext, key, iv)
print(data.hex())

decr = A.Decrypt("ctr", data, key, iv)
print(decr)
"""

import sys
import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from utils.Encryption import AESEncryption


def encrypt_image(path, image, mode, key, iv=None):

    BLOCK_SIZE = keySize = 16
    ivSize = BLOCK_SIZE if mode == "CBC" else 0

    imageOrig = cv2.imread(path+image)
    rowOrig, columnOrig, depthOrig = imageOrig.shape

    # Check for minimum width
    minWidth = (BLOCK_SIZE + BLOCK_SIZE) // depthOrig + 1

    # Convert original image data to bytes
    imageOrigBytes = imageOrig.tobytes()

    # Encrypt
    cipher = AESEncryption()
    # cipher = AES.new(key, AES.MODE_CBC, iv) if mode == "CBC" else AES.new(
    #    key, AES.MODE_ECB)

    imageOrigBytesPadded = pad(imageOrigBytes, BLOCK_SIZE)
    # ciphertext = cipher.encrypt(imageOrigBytesPadded)
    ciphertext = cipher.Encrypt(mode, imageOrigBytes, key, iv)

    paddedSize = len(imageOrigBytesPadded) - len(imageOrigBytes)
    void = columnOrig * depthOrig - ivSize - paddedSize

    if mode == "CBC":
        ivCiphertextVoid = iv + ciphertext + bytes(void)
    else:
        ivCiphertextVoid = ciphertext + bytes(void)

    imageEncrypted = np.frombuffer(ivCiphertextVoid, dtype=imageOrig.dtype).reshape(
        rowOrig + 1, columnOrig, depthOrig)

    cv2.imwrite(path+"topsecretEnc.bmp", imageEncrypted)
    return path+"topsecretEnc.bmp"

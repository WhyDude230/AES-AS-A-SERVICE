from flask import Flask, request, render_template, make_response, session, send_file
from flask_session import Session
import random
import uuid
import os
from utils.Encryption import AESEncryption
from utils.ImageEncryption import encrypt_image

app = Flask(__name__,  static_url_path='/static')


@app.route('/encrypt', methods=['POST', 'GET'])
def encrypt_data():
    print(request.form)
    cipher = AESEncryption()
    key = bytes.fromhex(request.form.get("key", "00"))
    mode = request.form.get("modes")
    iv = bytes.fromhex(request.form.get("iv", "00"))
    print(iv)
    plaintext = request.form.get("plaintext", "").encode()
    File = request.files.get("image")
    print(File)
    if File.filename != "":
        print(File.filename)
        path = os.getcwd()+"/images/"
        File.save(path + File.filename)
        encryption_path = encrypt_image(path, File.filename, mode, key, iv)
        return send_file(encryption_path, mimetype="image/bmp")
    ciphertext = cipher.Encrypt(mode, plaintext, key, iv)

    try:
        ciphertext = ciphertext.hex()
        ciphertext = "\t".join(AESEncryption.breakMessage(ciphertext, 32))
        return render_template("index.html", ciphertext=ciphertext)
    except:

        return render_template("index.html", ciphertext=ciphertext)


@app.route('/decrypt', methods=['POST', 'GET'])
def decrypt_data():
    cipher = AESEncryption()
    key = bytes.fromhex(request.form.get("key", "00"))
    mode = request.form.get("modes")
    iv = bytes.fromhex(request.form.get("iv", "00"))
    print(iv)
    ciphertext = bytes.fromhex(request.form.get("ciphertext", "00"))

    plaintext = cipher.Decrypt(mode, ciphertext, key, iv)

    try:
        plaintext = plaintext.decode()
        return render_template("index.html", plaintext=plaintext)
    except:
        return render_template("index.html", plaintext=plaintext)


@app.route('/', methods=['GET'])
def home():
    return render_template("index.html")


app.run(host="0.0.0.0", port="8080", debug=True)

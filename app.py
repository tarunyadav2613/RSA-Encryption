from flask import Flask, render_template, request, jsonify, send_file
import random
from sympy import randprime
from io import BytesIO
import base64
from PIL import Image
import numpy as np

app = Flask(__name__)

# Function to generate larger primes
def generate_large_prime(bits=8):
    return randprime(2**(bits - 1), 2**bits - 1)

# Greatest common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Modular inverse
def mod_inverse(e, phi):
    for d in range(2, phi):
        if (d * e) % phi == 1:
            return d
    return None

# RSA Key generation
def generate_keys(bits=8):
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while p == q:
        q = generate_large_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    e_choices = [3, 5, 17, 257, 65537]
    e = random.choice(e_choices)
    while gcd(e, phi) != 1:
        e = random.choice(e_choices)

    d = mod_inverse(e, phi)
    return p, q, e, d, n

# Global RSA keys
p, q, e, d, n = generate_keys()

@app.route("/")
def index():
    return render_template("index.html", p=p, q=q, public_key=(e, n), private_key=(d, n))

@app.route("/generate_keys", methods=["GET"])
def generate_new_keys():
    global p, q, e, d, n
    p, q, e, d, n = generate_keys()
    return jsonify({
        "p": p,
        "q": q,
        "public_key": f"({e}, {n})",
        "private_key": f"({d}, {n})"
    })

@app.route("/encrypt", methods=["POST"])
def encrypt():
    message = request.form["message"]
    encrypted_nums = [pow(ord(char), e, n) for char in message]
    encrypted_bytes = ",".join(map(str, encrypted_nums)).encode()
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    return render_template("index.html", encrypted=encrypted_b64, p=p, q=q, public_key=(e, n), private_key=(d, n))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    encrypted_text = request.form["encrypted_text"]
    try:
        encrypted_bytes = base64.b64decode(encrypted_text.encode())
        encrypted_nums = list(map(int, encrypted_bytes.decode().split(",")))
        decrypted_msg = "".join([chr(pow(num, d, n)) for num in encrypted_nums])
        return render_template("index.html", decrypted=decrypted_msg, p=p, q=q, public_key=(e, n), private_key=(d, n))
    except Exception as ex:
        return render_template("index.html", error=f"Decryption error: {str(ex)}", p=p, q=q, public_key=(e, n), private_key=(d, n))

@app.route("/encrypt_file", methods=["POST"])
def encrypt_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    content = file.read().decode()
    encrypted = [pow(ord(char), e, n) for char in content]
    encrypted_data = ",".join(map(str, encrypted))
    buffer = BytesIO()
    buffer.write(encrypted_data.encode())
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="encrypted.txt", mimetype="text/plain")

@app.route("/decrypt_file", methods=["POST"])
def decrypt_file():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    content = file.read().decode()
    try:
        nums = list(map(int, content.split(',')))
        decrypted = "".join([chr(pow(num, d, n)) for num in nums])
        buffer = BytesIO()
        buffer.write(decrypted.encode())
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="decrypted.txt", mimetype="text/plain")
    except Exception as ex:
        return f"Decryption error: {str(ex)}", 400

@app.route("/encrypt_image", methods=["POST"])
def encrypt_image():
    if 'image' not in request.files:
        return "No image part", 400
    img_file = request.files["image"]
    if img_file.filename == "":
        return "No selected image", 400

    try:
        image = Image.open(img_file).convert("RGB")
        arr = np.array(image)
        encrypted_arr = np.vectorize(lambda x: pow(int(x), e, n))(arr)

        buffer = BytesIO()
        np.save(buffer, encrypted_arr)
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="encrypted_image.npy", mimetype="application/octet-stream")
    except Exception as ex:
        return f"Encryption error: {str(ex)}", 400

@app.route("/decrypt_image", methods=["POST"])
def decrypt_image():
    if 'image_file' not in request.files:
        return "No image file part", 400
    enc_file = request.files["image_file"]
    if enc_file.filename == "":
        return "No selected file", 400

    try:
        enc_arr = np.load(enc_file)
        decrypted_arr = np.vectorize(lambda x: pow(int(x), d, n))(enc_arr)
        decrypted_arr = np.uint8(np.clip(decrypted_arr, 0, 255))

        image = Image.fromarray(decrypted_arr, mode="RGB")

        buffer = BytesIO()
        image.save(buffer, format="PNG")
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name="decrypted_image.png", mimetype="image/png")
    except Exception as ex:
        return f"Decryption error: {str(ex)}", 400

if __name__ == "__main__":
    app.run(debug=True)

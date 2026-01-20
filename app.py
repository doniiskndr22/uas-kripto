from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os
from PIL import Image
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.secret_key = "kunci_rahasia_untuk_session"  # Diperlukan untuk flash message

# --- FUNGSI LOGIKA KRIPTOGRAFI (Sama seperti sebelumnya) ---

def encrypt_logic(pdf_bytes, cover_image, password):
    try:
        # 1. AES Encryption
        salt = os.urandom(16)
        iv = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(pdf_bytes) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        final_data = salt + iv + ciphertext # Gabungan data
        
        # 2. LSB Steganography
        img = cover_image.convert('RGB')
        width, height = img.size
        pixels = img.load()
        
        length_bytes = len(final_data).to_bytes(4, 'big')
        full_payload = length_bytes + final_data
        
        if len(full_payload) > (width * height * 3) // 8:
            return None, "Gambar terlalu kecil untuk menampung file PDF ini."
            
        binary_data = ''.join(f'{byte:08b}' for byte in full_payload)
        idx = 0
        total_bits = len(binary_data)
        
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                if idx < total_bits: r = (r & ~1) | int(binary_data[idx]); idx += 1
                if idx < total_bits: g = (g & ~1) | int(binary_data[idx]); idx += 1
                if idx < total_bits: b = (b & ~1) | int(binary_data[idx]); idx += 1
                pixels[x, y] = (r, g, b)
                if idx >= total_bits: break
            if idx >= total_bits: break
            
        output = BytesIO()
        img.save(output, format="PNG")
        output.seek(0)
        return output, "Sukses"
    except Exception as e:
        return None, str(e)

def decrypt_logic(stego_image, password):
    try:
        img = stego_image.convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        # Baca Header 32 bit
        header_bits = ""
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                header_bits += str(r & 1); 
                if len(header_bits) >= 32: break
                header_bits += str(g & 1)
                if len(header_bits) >= 32: break
                header_bits += str(b & 1)
                if len(header_bits) >= 32: break
            if len(header_bits) >= 32: break
            
        data_len = int(header_bits, 2)
        total_needed = 32 + (data_len * 8)
        
        # Baca Payload
        bits = ""
        count = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                for val in [r, g, b]:
                    bits += str(val & 1); count += 1
                    if count >= total_needed: break
                if count >= total_needed: break
            if count >= total_needed: break
            
        payload_bits = bits[32:]
        encrypted_data = bytearray()
        for i in range(0, len(payload_bits), 8):
            encrypted_data.append(int(payload_bits[i:i+8], 2))
            
        # AES Decryption
        salt = bytes(encrypted_data[:16])
        iv = bytes(encrypted_data[16:32])
        ciphertext = bytes(encrypted_data[32:])
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        original_pdf = unpadder.update(padded_data) + unpadder.finalize()
        
        output = BytesIO(original_pdf)
        output.seek(0)
        return output, "Sukses"
    except Exception:
        return None, "Gagal: Password salah atau data rusak."

# --- ROUTES (JALUR WEB) ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'pdf_file' not in request.files or 'cover_image' not in request.files or 'password' not in request.form:
        flash("Data tidak lengkap!", "error")
        return redirect(url_for('index'))
    
    pdf = request.files['pdf_file']
    cover = request.files['cover_image']
    password = request.form['password']
    
    if pdf.filename == '' or cover.filename == '':
        flash("Pilih file terlebih dahulu.", "error")
        return redirect(url_for('index'))

    pdf_bytes = pdf.read()
    cover_img = Image.open(cover)
    
    result, msg = encrypt_logic(pdf_bytes, cover_img, password)
    
    if result:
        return send_file(result, mimetype='image/png', as_attachment=True, download_name='stego_encrypted.png')
    else:
        flash(msg, "error")
        return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'stego_image' not in request.files or 'password' not in request.form:
        flash("Data tidak lengkap!", "error")
        return redirect(url_for('index'))
        
    stego = request.files['stego_image']
    password = request.form['password']
    
    stego_img = Image.open(stego)
    result, msg = decrypt_logic(stego_img, password)
    
    if result:
        return send_file(result, mimetype='application/pdf', as_attachment=True, download_name='document_decrypted.pdf')
    else:
        flash(msg, "error")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
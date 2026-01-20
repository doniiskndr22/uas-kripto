import os
from PIL import Image
from io import BytesIO
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- 1. MODUL ENKRIPSI & STEGANOGRAFI ---
def process_encryption(pdf_bytes, cover_image, password):
    try:
        # A. PROSES KRIPTOGRAFI (AES-256)
        # 1. Buat Salt & IV (Random)
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # 2. Turunkan Kunci dari Password (PBKDF2)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # 3. Padding Data PDF (PKCS7) agar pas blok 128-bit
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(pdf_bytes) + padder.finalize()
        
        # 4. Enkripsi AES Mode CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Gabungkan data: [SALT(16)] + [IV(16)] + [CIPHERTEXT]
        final_data = salt + iv + ciphertext
        
        # B. PROSES STEGANOGRAFI (LSB)
        img = cover_image.convert('RGB')
        width, height = img.size
        pixels = img.load()
        
        # Header Panjang Data (4 byte) agar tahu kapan berhenti baca
        length_bytes = len(final_data).to_bytes(4, 'big')
        full_payload = length_bytes + final_data
        
        # Cek Kapasitas Gambar
        max_bytes = (width * height * 3) // 8
        if len(full_payload) > max_bytes:
            return None, f"Gagal: Gambar kekecilan! Butuh {len(full_payload)} bytes, tersedia {max_bytes} bytes."
        
        # Konversi ke Biner
        binary_data = ''.join(f'{byte:08b}' for byte in full_payload)
        data_idx = 0
        total_bits = len(binary_data)
        
        # Sisipkan bit per bit ke LSB
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                
                if data_idx < total_bits:
                    r = (r & ~1) | int(binary_data[data_idx])
                    data_idx += 1
                if data_idx < total_bits:
                    g = (g & ~1) | int(binary_data[data_idx])
                    data_idx += 1
                if data_idx < total_bits:
                    b = (b & ~1) | int(binary_data[data_idx])
                    data_idx += 1
                
                pixels[x, y] = (r, g, b)
                if data_idx >= total_bits:
                    break
            if data_idx >= total_bits:
                break
        
        # Simpan ke memori
        output_buffer = BytesIO()
        img.save(output_buffer, format="PNG")
        return output_buffer.getvalue(), "Sukses"
        
    except Exception as e:
        return None, f"Error Sistem: {str(e)}"

# --- 2. MODUL DEKRIPSI & EKSTRAKSI ---
def process_decryption(stego_image, password):
    try:
        # A. EKSTRAKSI LSB
        img = stego_image.convert('RGB')
        pixels = img.load()
        width, height = img.size
        
        # Baca 32 bit pertama (Header Panjang)
        header_bits = ""
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                header_bits += str(r & 1)
                if len(header_bits) >= 32: break
                header_bits += str(g & 1)
                if len(header_bits) >= 32: break
                header_bits += str(b & 1)
                if len(header_bits) >= 32: break
            if len(header_bits) >= 32: break
            
        data_length = int(header_bits, 2)
        total_bits_needed = 32 + (data_length * 8)
        
        # Baca Payload Sesuai Panjang
        accumulated_bits = ""
        count = 0
        for y in range(height):
            for x in range(width):
                r, g, b = pixels[x, y]
                for val in [r, g, b]:
                    accumulated_bits += str(val & 1)
                    count += 1
                    if count >= total_bits_needed: break
                if count >= total_bits_needed: break
            if count >= total_bits_needed: break
            
        payload_bits = accumulated_bits[32:] # Buang header
        
        # Ubah Biner ke Bytes
        encrypted_data = bytearray()
        for i in range(0, len(payload_bits), 8):
            byte_val = payload_bits[i:i+8]
            if len(byte_val) == 8:
                encrypted_data.append(int(byte_val, 2))
        
        # B. PROSES DEKRIPSI (AES-256)
        # Pisahkan komponen (Salt, IV, Ciphertext)
        # PENTING: Pakai bytes() agar tidak error tipe data
        salt = bytes(encrypted_data[:16])
        iv = bytes(encrypted_data[16:32])
        ciphertext = bytes(encrypted_data[32:])
        
        # Turunkan Kunci (Sama seperti saat enkripsi)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Dekripsi
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpadding
        unpadder = padding.PKCS7(128).unpadder()
        original_pdf = unpadder.update(padded_data) + unpadder.finalize()
        
        return original_pdf, "Sukses"
        
    except Exception as e:
        return None, "Gagal: Password salah atau gambar bukan hasil enkripsi yang benar."
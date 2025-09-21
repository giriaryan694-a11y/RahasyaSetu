import sys, os, struct, wave, math
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QFont
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# === Utility Functions ===
def encrypt_payload(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM)
    enc_data, tag = cipher.encrypt_and_digest(data)
    return salt + cipher.nonce + tag + enc_data

def decrypt_payload(data: bytes, password: str) -> bytes:
    salt = data[:16]
    nonce = data[16:32]
    tag = data[32:48]
    enc_data = data[48:]
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(enc_data, tag)

def hide_in_image(carrier_path, payload_bytes, out_path, progress_signal=None):
    img = Image.open(carrier_path)
    img = img.convert("RGBA")
    pixels = list(img.getdata())
    if len(payload_bytes)*8 > len(pixels)*4:
        raise ValueError("Carrier image too small")

    new_pixels = []
    payload_bits = ''.join(f"{b:08b}" for b in payload_bytes)
    bit_idx = 0
    total_bits = len(payload_bits)
    for idx, (r,g,b,a) in enumerate(pixels):
        if bit_idx < total_bits:
            r = (r & 0xFE) | int(payload_bits[bit_idx]); bit_idx+=1
        if bit_idx < total_bits:
            g = (g & 0xFE) | int(payload_bits[bit_idx]); bit_idx+=1
        if bit_idx < total_bits:
            b = (b & 0xFE) | int(payload_bits[bit_idx]); bit_idx+=1
        if bit_idx < total_bits:
            a = (a & 0xFE) | int(payload_bits[bit_idx]); bit_idx+=1
        new_pixels.append((r,g,b,a))
        if progress_signal and idx % 500 == 0:
            progress_signal.emit(int(idx/len(pixels)*100))
    img.putdata(new_pixels)
    img.save(out_path)
    if progress_signal:
        progress_signal.emit(100)

def extract_from_image(carrier_path, payload_len, progress_signal=None):
    img = Image.open(carrier_path)
    img = img.convert("RGBA")
    pixels = list(img.getdata())
    total_bits = payload_len * 8
    bits = []
    for idx, (r,g,b,a) in enumerate(pixels):
        for channel in (r,g,b,a):
            bits.append(str(channel & 1))
            if len(bits) >= total_bits:
                break
        if len(bits) >= total_bits:
            break
        if progress_signal and idx % 500 == 0:
            progress_signal.emit(int(idx/len(pixels)*100))
    data_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = int(''.join(bits[i:i+8]), 2)
        data_bytes.append(byte)
    if progress_signal:
        progress_signal.emit(100)
    return bytes(data_bytes)

# For WAV LSB embedding
def hide_in_wav(carrier_path, payload_bytes, out_path, progress_signal=None):
    with wave.open(carrier_path, 'rb') as wf:
        params = wf.getparams()
        frames = bytearray(wf.readframes(params.nframes))
    if len(payload_bytes)*8 > len(frames):
        raise ValueError("Carrier WAV too small")
    for i, byte in enumerate(payload_bytes):
        for bit in range(8):
            frames[i*8 + bit] &= 0xFE
            frames[i*8 + bit] |= (byte >> (7-bit)) & 1
        if progress_signal and i % 500 == 0:
            progress_signal.emit(int(i/len(payload_bytes)*100))
    with wave.open(out_path, 'wb') as wf:
        wf.setparams(params)
        wf.writeframes(frames)
    if progress_signal:
        progress_signal.emit(100)

def extract_from_wav(carrier_path, payload_len, progress_signal=None):
    with wave.open(carrier_path, 'rb') as wf:
        frames = bytearray(wf.readframes(wf.getnframes()))
    extracted = bytearray()
    for i in range(payload_len):
        byte = 0
        for bit in range(8):
            byte = (byte << 1) | (frames[i*8 + bit] & 1)
        extracted.append(byte)
        if progress_signal and i % 500 == 0:
            progress_signal.emit(int(i/payload_len*100))
    if progress_signal:
        progress_signal.emit(100)
    return bytes(extracted)

# === PyQt6 GUI Worker ===
class StegoWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)

    def __init__(self, src_file, carrier_file, output_file, password=None, mode="hide"):
        super().__init__()
        self.src_file = src_file
        self.carrier_file = carrier_file
        self.output_file = output_file
        self.password = password
        self.mode = mode

    def run(self):
        try:
            if self.mode == "hide":
                with open(self.src_file, "rb") as f:
                    data = f.read()
                if self.password:
                    data = encrypt_payload(data, self.password)
                ext_bytes = os.path.splitext(self.src_file)[1].encode().ljust(8,b'\x00')
                payload = ext_bytes + struct.pack(">I", len(data)) + data
                ext = self.carrier_file.split('.')[-1].lower()
                if ext in ['png','jpg','jpeg','bmp']:
                    hide_in_image(self.carrier_file, payload, self.output_file, self.progress)
                elif ext in ['wav']:
                    hide_in_wav(self.carrier_file, payload, self.output_file, self.progress)
                else:
                    self.finished.emit("Unsupported carrier type yet!")
                    return
                self.finished.emit(f"Hidden successfully in {self.output_file}")
            else:
                ext = self.carrier_file.split('.')[-1].lower()
                if ext in ['png','jpg','jpeg','bmp']:
                    with open(self.carrier_file, 'rb') as f:
                        carrier_data = f.read()
                    header = extract_from_image(self.carrier_file, 12, self.progress)
                elif ext in ['wav']:
                    header = extract_from_wav(self.carrier_file, 12, self.progress)
                else:
                    self.finished.emit("Unsupported carrier type yet!")
                    return
                ext_name = header[:8].strip(b'\x00').decode()
                payload_len = struct.unpack(">I", header[8:12])[0]
                if ext in ['png','jpg','jpeg','bmp']:
                    extracted = extract_from_image(self.carrier_file, payload_len+12, self.progress)[12:]
                elif ext in ['wav']:
                    extracted = extract_from_wav(self.carrier_file, payload_len+12, self.progress)[12:]
                if self.password:
                    extracted = decrypt_payload(extracted, self.password)
                with open(self.output_file, "wb") as f:
                    f.write(extracted)
                self.finished.emit(f"Extracted successfully to {self.output_file}")
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")

# === PyQt6 GUI ===
class RahasyaSetu(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RahasyaSetu - Made by Aryan Giri")
        self.resize(600, 300)
        self.setStyleSheet("background-color: #0f0f0f; color: #00ff00;")
        layout = QVBoxLayout()

        self.label = QLabel("Select files and hide/extract them securely")
        self.label.setFont(QFont("Courier", 12))
        layout.addWidget(self.label)

        self.hide_btn = QPushButton("Hide File")
        self.hide_btn.setStyleSheet("background-color: #111111; color: #00ff00;")
        self.hide_btn.clicked.connect(self.hide_file)
        layout.addWidget(self.hide_btn)

        self.extract_btn = QPushButton("Extract File")
        self.extract_btn.setStyleSheet("background-color: #111111; color: #00ff00;")
        self.extract_btn.clicked.connect(self.extract_file)
        layout.addWidget(self.extract_btn)

        self.progress = QProgressBar()
        self.progress.setStyleSheet("QProgressBar {background: #111; color:#00ff00;}")
        layout.addWidget(self.progress)

        self.pass_checkbox = QCheckBox("Encrypt with password")
        layout.addWidget(self.pass_checkbox)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setVisible(False)
        layout.addWidget(self.password_input)
        self.pass_checkbox.stateChanged.connect(lambda: self.password_input.setVisible(self.pass_checkbox.isChecked()))

        self.setLayout(layout)

    def hide_file(self):
        src_file, _ = QFileDialog.getOpenFileName(self, "Select file to hide")
        carrier_file, _ = QFileDialog.getOpenFileName(self, "Select carrier file")
        output_file, _ = QFileDialog.getSaveFileName(self, "Save output file as")
        if src_file and carrier_file and output_file:
            password = self.password_input.text() if self.pass_checkbox.isChecked() else None
            self.worker = StegoWorker(src_file, carrier_file, output_file, password, "hide")
            self.worker.progress.connect(self.progress.setValue)
            self.worker.finished.connect(self.show_message)
            self.worker.start()

    def extract_file(self):
        carrier_file, _ = QFileDialog.getOpenFileName(self, "Select carrier file")
        output_file, _ = QFileDialog.getSaveFileName(self, "Save extracted file as")
        if carrier_file and output_file:
            password = self.password_input.text() if self.pass_checkbox.isChecked() else None
            self.worker = StegoWorker(None, carrier_file, output_file, password, "extract")
            self.worker.progress.connect(self.progress.setValue)
            self.worker.finished.connect(self.show_message)
            self.worker.start()

    def show_message(self, msg):
        self.label.setText(msg)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RahasyaSetu()
    window.show()
    sys.exit(app.exec())

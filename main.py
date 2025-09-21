#!/usr/bin/env python3
"""
RahasyaSetu — Client-side steganography GUI (Python)
Made by Aryan Giri

Features:
- GUI (PyQt6) with hacker theme, drag & drop
- Hide / Extract files into/from Images (PNG/JPG/BMP), WAV, MP3 (ID3 APIC), MP4 (frame LSB)
- Optional AES-GCM password encryption (PBKDF2-derived key)
- Progress bar, capacity checks, headers with filename+length+encryption metadata
- Fallback append method for unsupported formats

Dependencies:
pip install PyQt6 pillow pycryptodome mutagen moviepy numpy
Also ensure ffmpeg is installed for moviepy (system package).

Note: Use only on files and repos you control or have permission to test.
"""
import sys, os, struct, math, traceback
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QLabel,
                             QFileDialog, QLineEdit, QProgressBar, QCheckBox, QHBoxLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import numpy as np
from mutagen.id3 import ID3, APIC, ID3NoHeaderError
from moviepy.editor import VideoFileClip
import io
import wave

# --------------------------
# Configuration / constants
# --------------------------
MAGIC = b'RAHASYA3'   # 8 bytes marker (versioned)
PBKDF2_ITERS = 200_000
AES_NONCE_BYTES = 12
SALT_BYTES = 16

# --------------------------
# Header format (binary)
# --------------------------
# [MAGIC (8)] [flags (1)] [reserved (1)] [payload_len (4 big-endian)] [fname_len (2)] [fname bytes]
# if flags & 1 (encrypted): [salt_len (1)] [salt bytes] [iv_len (1)] [iv bytes]
#
# flags bit0 = encrypted

def make_header(fname: str, payload_len: int, encrypted: bool=False, salt: bytes=None, iv: bytes=None) -> bytes:
    fname_b = fname.encode('utf-8')
    hdr = bytearray()
    hdr += MAGIC
    flags = 1 if encrypted else 0
    hdr.append(flags & 0xFF)
    hdr.append(0)  # reserved
    hdr += struct.pack('>I', payload_len)
    hdr += struct.pack('>H', len(fname_b))
    hdr += fname_b
    if encrypted:
        hdr.append(len(salt))
        hdr += salt
        hdr.append(len(iv))
        hdr += iv
    return bytes(hdr)

def parse_header(buf: bytes, offset=0):
    if offset + len(MAGIC) + 8 > len(buf): return None
    if buf[offset:offset+len(MAGIC)] != MAGIC: return None
    idx = offset + len(MAGIC)
    flags = buf[idx]; idx += 1
    idx += 1  # reserved
    payload_len = struct.unpack('>I', buf[idx:idx+4])[0]; idx += 4
    fname_len = struct.unpack('>H', buf[idx:idx+2])[0]; idx += 2
    if idx + fname_len > len(buf): return None
    fname = buf[idx: idx+fname_len].decode('utf-8'); idx += fname_len
    encrypted = bool(flags & 1)
    salt = iv = None
    if encrypted:
        if idx + 1 > len(buf): return None
        slen = buf[idx]; idx += 1
        if idx + slen > len(buf): return None
        salt = buf[idx: idx+slen]; idx += slen
        ilen = buf[idx]; idx += 1
        if idx + ilen > len(buf): return None
        iv = buf[idx: idx+ilen]; idx += ilen
    return {'payload_len': payload_len, 'filename': fname, 'encrypted': encrypted, 'salt': salt, 'iv': iv, 'header_len': idx-offset}

# --------------------------
# Crypto helpers (PyCryptodome)
# --------------------------
def derive_key(password: str, salt: bytes, iterations=PBKDF2_ITERS) -> bytes:
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=iterations)

def encrypt_bytes(plain: bytes, password: str):
    salt = get_random_bytes(SALT_BYTES)
    key = derive_key(password, salt)
    iv = get_random_bytes(AES_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plain)
    # store salt + iv + tag + ciphertext as data (tag included inside returned payload or in header)
    # We'll keep salt & iv in header, and return ciphertext+tag
    return {'cipher': ct + tag, 'salt': salt, 'iv': iv}

def decrypt_bytes(cipher_and_tag: bytes, password: str, salt: bytes, iv: bytes):
    key = derive_key(password, salt)
    tag = cipher_and_tag[-16:]
    ct = cipher_and_tag[:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plain = cipher.decrypt_and_verify(ct, tag)
    return plain

# --------------------------
# Carrier-specific embedding
# --------------------------

def capacity_for_image(path):
    img = Image.open(path)
    w,h = img.size
    # we'll use 3 channels (RGB) to be safe
    return w * h * 3 // 8  # bytes

def embed_image_lsb(carrier_path, payload_bytes, out_path, progress_callback=None):
    img = Image.open(carrier_path).convert('RGBA')
    pixels = list(img.getdata())
    total_pixels = len(pixels)
    total_bits = len(payload_bytes) * 8
    if total_bits > total_pixels * 3:
        raise ValueError("Payload too large for image (capacity {})".format(total_pixels*3//8))
    bit_str = ''.join(f'{b:08b}' for b in payload_bytes)
    bit_idx = 0
    new_pixels = []
    for i, (r,g,b,a) in enumerate(pixels):
        if bit_idx < total_bits:
            r = (r & 0xFE) | int(bit_str[bit_idx]); bit_idx += 1
        if bit_idx < total_bits:
            g = (g & 0xFE) | int(bit_str[bit_idx]); bit_idx += 1
        if bit_idx < total_bits:
            b = (b & 0xFE) | int(bit_str[bit_idx]); bit_idx += 1
        new_pixels.append((r,g,b,a))
        if progress_callback and i % 1024 == 0:
            progress_callback(int((i/total_pixels)*100))
    img.putdata(new_pixels)
    img.save(out_path)
    if progress_callback:
        progress_callback(100)

def extract_image_lsb(carrier_path, expected_total_bytes, progress_callback=None):
    img = Image.open(carrier_path).convert('RGBA')
    pixels = list(img.getdata())
    bits_needed = expected_total_bytes * 8
    bits = []
    for i, (r,g,b,a) in enumerate(pixels):
        for ch in (r,g,b):
            bits.append(str(ch & 1))
            if len(bits) >= bits_needed:
                break
        if len(bits) >= bits_needed:
            break
        if progress_callback and i % 1024 == 0:
            progress_callback(int((i/len(pixels))*100))
    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = int(''.join(bits[i:i+8]), 2)
        data.append(byte)
    if progress_callback:
        progress_callback(100)
    return bytes(data)

def capacity_for_wav(path):
    with wave.open(path, 'rb') as wf:
        nframes = wf.getnframes()
        sampwidth = wf.getsampwidth()
        # we'll embed 1 bit per byte of audio frame
        return (nframes * sampwidth) // 8

def embed_wav_lsb(carrier_path, payload_bytes, out_path, progress_callback=None):
    with wave.open(carrier_path, 'rb') as rf:
        params = rf.getparams()
        frames = bytearray(rf.readframes(params.nframes))
    total_bits = len(payload_bytes) * 8
    if total_bits > len(frames):
        raise ValueError("Payload too large for WAV (capacity {} bytes)".format(len(frames)//8))
    bitstr = ''.join(f'{b:08b}' for b in payload_bytes)
    for i in range(len(bitstr)):
        frames[i] = (frames[i] & 0xFE) | int(bitstr[i])
        if progress_callback and i % 4096 == 0:
            progress_callback(int((i/len(bitstr))*100))
    with wave.open(out_path, 'wb') as wf:
        wf.setparams(params)
        wf.writeframes(frames)
    if progress_callback: progress_callback(100)

def extract_wav_lsb(carrier_path, expected_total_bytes, progress_callback=None):
    with wave.open(carrier_path, 'rb') as rf:
        frames = bytearray(rf.readframes(rf.getnframes()))
    bits_needed = expected_total_bytes * 8
    bits = []
    for i in range(bits_needed):
        bits.append(str(frames[i] & 1))
        if progress_callback and i % 4096 == 0:
            progress_callback(int((i/bits_needed)*100))
    data = bytearray()
    for i in range(0, len(bits), 8):
        data.append(int(''.join(bits[i:i+8]), 2))
    if progress_callback: progress_callback(100)
    return bytes(data)

def embed_mp3_id3(carrier_path, payload_bytes, out_path):
    try:
        tags = ID3(carrier_path)
    except ID3NoHeaderError:
        tags = ID3()
    # Add APIC frame storing binary payload (use description to identify)
    frame = APIC(encoding=3, mime='application/octet-stream', type=3, desc='RahasyaSetu', data=payload_bytes)
    tags.add(frame)
    tags.save(out_path)

def extract_mp3_id3(carrier_path):
    try:
        tags = ID3(carrier_path)
    except Exception:
        return None
    for apic in tags.getall('APIC'):
        if getattr(apic, 'desc', '') == 'RahasyaSetu':
            return apic.data
    return None

def append_method(carrier_path, payload_bytes, out_path):
    with open(carrier_path, 'rb') as f:
        c = f.read()
    with open(out_path, 'wb') as f:
        f.write(c)
        f.write(payload_bytes)

# MP4 embedding using moviepy (frame LSB)
def capacity_for_mp4(path):
    clip = VideoFileClip(path)
    w,h = clip.size
    fps = clip.fps
    nframes = int(clip.duration * fps)
    clip.reader.close()
    clip.audio = None
    # capacity in bytes: frames * pixels * 3 bits / 8
    return (nframes * w * h * 3) // 8

def embed_mp4_frames(carrier_path, payload_bytes, out_path, progress_callback=None):
    clip = VideoFileClip(carrier_path)
    w,h = clip.size
    fps = clip.fps
    total_frames = int(clip.duration * fps)
    total_bits = len(payload_bytes) * 8
    cap_bits = total_frames * w * h * 3
    if total_bits > cap_bits:
        clip.reader.close()
        raise ValueError("Payload too large for video carrier (capacity {} bytes)".format(cap_bits//8))

    bitstr = ''.join(f'{b:08b}' for b in payload_bytes)
    bit_iter = iter(bitstr)

    def process_frame(frame):
        # frame: numpy array HxWx3 (RGB)
        nonlocal bit_iter
        h_ = frame.shape[0]; w_ = frame.shape[1]
        flat = frame.reshape(-1, 3)
        # modify LSBs of R,G,B sequentially for as many bits as available in this frame
        for i in range(flat.shape[0]):
            for ch in range(3):
                try:
                    b = next(bit_iter)
                except StopIteration:
                    return frame
                flat[i, ch] = (int(flat[i, ch]) & 0xFE) | int(b)
        return flat.reshape(h_, w_, 3)

    # Use fl_image to apply function to all frames; this will iterate frames and call process_frame
    # But fl_image expects a function that returns a frame for each input. We'll keep iter state globally.
    new_clip = clip.fl_image(process_frame)
    # write new video (may take time)
    new_clip.write_videofile(out_path, codec='libx264', audio_codec='aac', verbose=False, logger=None)
    clip.reader.close()
    if progress_callback:
        progress_callback(100)

def extract_mp4_frames(carrier_path, expected_total_bytes, progress_callback=None):
    clip = VideoFileClip(carrier_path)
    w,h = clip.size
    fps = clip.fps
    total_frames = int(clip.duration * fps)
    bits_needed = expected_total_bytes * 8
    bits = []
    count = 0
    for frame in clip.iter_frames():
        flat = frame.reshape(-1, 3)
        for pixel in flat:
            for ch in range(3):
                bits.append(str(int(pixel[ch]) & 1))
                if len(bits) >= bits_needed:
                    clip.reader.close()
                    return bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8))
        count += 1
        if progress_callback and count % 10 == 0:
            progress_callback(int((count/total_frames)*100))
    clip.reader.close()
    if progress_callback:
        progress_callback(100)
    return bytes(int(''.join(bits[i:i+8]), 2) for i in range(0, len(bits), 8))

# --------------------------
# Worker thread (QThread) — does heavy lifting
# --------------------------
class Worker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    def __init__(self, carrier_path, payload_path, out_path, mode='hide', password=None):
        super().__init__()
        self.carrier_path = carrier_path
        self.payload_path = payload_path
        self.out_path = out_path
        self.mode = mode
        self.password = password

    def run(self):
        try:
            if self.mode == 'hide':
                # read payload
                with open(self.payload_path, 'rb') as f:
                    payload_data = f.read()
                encrypted = False
                salt = iv = None
                if self.password:
                    enc = encrypt_bytes(payload_data, self.password)
                    payload_data = enc['cipher']  # ciphertext + tag
                    salt = enc['salt']; iv = enc['iv']
                    encrypted = True
                # prepare header + payload
                header = make_header(os.path.basename(self.payload_path), len(payload_data), encrypted, salt, iv)
                payload_container = header + payload_data

                # detect carrier type
                ext = os.path.splitext(self.carrier_path)[1].lower().strip('.')
                # capacity check
                if ext in ('png','jpg','jpeg','bmp'):
                    cap = capacity_for_image(self.carrier_path)
                    if len(payload_container) > cap:
                        raise ValueError(f'Payload+header ({len(payload_container)} bytes) too large for image capacity {cap} bytes')
                    embed_image_lsb(self.carrier_path, payload_container, self.out_path, progress_callback=self.progress.emit)
                    self.finished.emit(f'Embedded into image: {self.out_path}')
                    return
                elif ext == 'wav':
                    cap = capacity_for_wav(self.carrier_path)
                    if len(payload_container) > cap:
                        raise ValueError(f'Payload+header too large for WAV capacity {cap} bytes')
                    embed_wav_lsb(self.carrier_path, payload_container, self.out_path, progress_callback=self.progress.emit)
                    self.finished.emit(f'Embedded into WAV: {self.out_path}')
                    return
                elif ext == 'mp3':
                    # ID3v2 APIC embedding
                    embed_bytes = payload_container
                    embed_mp3_id3(self.carrier_path, embed_bytes, self.out_path)
                    self.progress.emit(100)
                    self.finished.emit(f'Embedded into MP3 ID3 APIC: {self.out_path}')
                    return
                elif ext == 'mp4' or ext == 'mov' or ext == 'm4v':
                    cap = capacity_for_mp4(self.carrier_path)
                    if len(payload_container) > cap:
                        raise ValueError(f'Payload+header too large for MP4 capacity {cap} bytes')
                    embed_mp4_frames(self.carrier_path, payload_container, self.out_path, progress_callback=self.progress.emit)
                    self.finished.emit(f'Embedded into MP4 frames: {self.out_path}')
                    return
                else:
                    # fallback: append
                    append_method(self.carrier_path, payload_container, self.out_path)
                    self.progress.emit(100)
                    self.finished.emit(f'Appended payload to file EOF: {self.out_path}')
                    return

            else:  # extract
                ext = os.path.splitext(self.carrier_path)[1].lower().strip('.')
                raw = None
                if ext in ('png','jpg','jpeg','bmp'):
                    # read first chunk of bytes via LSB to get header length guess: header length unknown, but header is small
                    # we'll first read first 512 bytes to parse header
                    sample_head = extract_image_lsb(self.carrier_path, 512, progress_callback=None)
                    hdr = parse_header(sample_head, 0)
                    if not hdr:
                        # fallback: try searching appended marker at EOF
                        # read entire file bytes and search
                        with open(self.carrier_path, 'rb') as f: data=f.read()
                        idx = data.rfind(MAGIC)
                        if idx == -1:
                            self.finished.emit('No RahasyaSetu header found (image).')
                            return
                        hdr = parse_header(data, idx)
                        if not hdr:
                            self.finished.emit('Header parse failed.')
                            return
                        # get payload bytes following header from append
                        payload_bytes = data[idx + hdr['header_len']: idx + hdr['header_len'] + hdr['payload_len']]
                        raw = payload_bytes
                    else:
                        # got header from LSB first chunk
                        payload_total = hdr['header_len'] + hdr['payload_len']
                        data_all = extract_image_lsb(self.carrier_path, payload_total, progress_callback=self.progress.emit)
                        hdr2 = parse_header(data_all, 0)
                        if not hdr2:
                            self.finished.emit('Header parse failed after reading image LSB.')
                            return
                        raw = data_all[hdr2['header_len'] : hdr2['header_len'] + hdr2['payload_len']]
                        hdr = hdr2
                elif ext == 'wav':
                    # similar approach: read initial bytes via LSB to parse header
                    sample_head = extract_wav_lsb(self.carrier_path, 512, progress_callback=None)
                    hdr = parse_header(sample_head, 0)
                    if not hdr:
                        # fallback: search appended EOF marker
                        with open(self.carrier_path, 'rb') as f: data=f.read()
                        idx = data.rfind(MAGIC)
                        if idx == -1:
                            self.finished.emit('No RahasyaSetu header found (wav).')
                            return
                        hdr = parse_header(data, idx)
                        payload_bytes = data[idx + hdr['header_len']: idx + hdr['header_len'] + hdr['payload_len']]
                        raw = payload_bytes
                    else:
                        payload_total = hdr['header_len'] + hdr['payload_len']
                        data_all = extract_wav_lsb(self.carrier_path, payload_total, progress_callback=self.progress.emit)
                        hdr2 = parse_header(data_all, 0)
                        if not hdr2:
                            self.finished.emit('Header parse failed after reading wav LSB.')
                            return
                        raw = data_all[hdr2['header_len'] : hdr2['header_len'] + hdr2['payload_len']]
                        hdr = hdr2
                elif ext == 'mp3':
                    data = extract_mp3_id3(self.carrier_path)
                    if not data:
                        # fallback: try appended EOF
                        with open(self.carrier_path, 'rb') as f: d=f.read(); idx = d.rfind(MAGIC)
                        if idx == -1:
                            self.finished.emit('No RahasyaSetu data found in MP3.')
                            return
                        hdr = parse_header(d, idx)
                        raw = d[idx + hdr['header_len']: idx + hdr['header_len'] + hdr['payload_len']]
                    else:
                        hdr = parse_header(data, 0)
                        if not hdr:
                            self.finished.emit('No valid header inside MP3 APIC frame.')
                            return
                        raw = data[hdr['header_len']: hdr['header_len'] + hdr['payload_len']]
                elif ext in ('mp4','mov','m4v'):
                    # try LSB frame extraction: first read small head
                    sample_head = extract_mp4_frames(self.carrier_path, 512, progress_callback=None)
                    hdr = parse_header(sample_head, 0)
                    if not hdr:
                        # fallback 
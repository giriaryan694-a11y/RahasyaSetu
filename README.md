# RahasyaSetu

**RahasyaSetu** —  Steganography Tool  

---

## Overview

RahasyaSetu is a hacker-themed steganography application that lets you **hide and extract files** in various carrier formats:

- **Images**: PNG, JPG, BMP (LSB method)
- **Audio**: WAV (LSB), MP3 (ID3v2 APIC frame)
- **Video**: MP4 (frame LSB)
- **Generic files**: Append fallback method

Additional features:

- **Optional AES-GCM encryption** for payloads with password protection.
- **Progress bar** for large files.
- Responsive **GUI using PyQt6** with drag-and-drop support.
- Headers storing payload filename, length, encryption info.

> ⚠️ **Use ethically**. Only hide/extract files on your own or authorized data.

---

## Features

- **Hacker-themed GUI**: Green-on-black, made to look like a terminal/cyber interface.
- **Drag & Drop support** for carrier files.
- **Hide/Extract buttons** with progress bar.
- **Optional encryption** using password (AES-GCM + PBKDF2).
- **Supports multiple carrier types**.
- **Capacity checks** to prevent oversized payloads.

---

## Installation

### Dependencies

```bash
pip install -r requirements.txt
```
### System Requirements:

• Python 3.10+

• ffmpeg installed for video (MP4) processing.


### Install ffmpeg on Linux:
```
sudo apt install ffmpeg
```
### Install ffmpeg on Windows:

• 1. Download: https://ffmpeg.org/download.html


• 2. Add ffmpeg bin directory to your PATH.

## Usage 

### 1. Run the GUI:
```
python main.py
```
### 3. Hide a file:

**Choose a carrier file (image/audio/video/other)**

**Choose a payload file to hide**

**Optional: Enable "Encrypt payload" and enter a password**

**Click Hide → and choose output filename**

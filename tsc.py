#!/bin/python3

# ---------------------------------------------------------------------
# (c) 2026 TSC, T-Spine Code by Subhrajit Sain
# T-Spine Code version 1.0
# ---------------------------------------------------------------------
# T-Spine Code is licensed under the IDFCPL 1.0 License
# https://github.com/SubhrajitSain/IDFCPL
# ---------------------------------------------------------------------

import os

# this is to prevent opencv and qt logs
# qt was removed, but i am still keeping this
os.environ["OPENCV_LOG_LEVEL"] = "FATAL"
os.environ["OPENCV_FFMPEG_LOGLEVEL"] = "-8"
os.environ["QT_LOGGING_RULES"] = "*=false"
if "QT_QPA_PLATFORM" not in os.environ and "WAYLAND_DISPLAY" in os.environ:
    os.environ["QT_QPA_PLATFORM"] = "xcb"

import argparse
import sys
import csv
import math
import hashlib
import hmac
import base64
import wave
import struct
import tempfile
import subprocess
from PIL import Image, ImageDraw, ImageColor, ImageGrab
import numpy as np
import cv2
from reedsolo import RSCodec
from cryptography.fernet import Fernet
from colorama import Fore, Back, Style, init
import zstandard as zstd

init(autoreset=True)

class TSpineCode:
    # cell color pallette (RGB)
    PALETTE = [
        (255, 255, 255),
        (0, 0, 0),
        (255, 0, 0),
        (0, 0, 255),
        (0, 255, 0),
        (0, 255, 255),
        (255, 0, 255),
        (255, 255, 0)
    ]
    # pallete is WKRBGCMY

    # how much error correction to put corresponding to arg
    ECC_LEVELS = {
        "0": 0, "no": 0, "none": 0, "off": 0, "false": 0,
        "1": 4, "low": 4,
        "2": 12, "mid": 12, "med": 12, "normal": 12,
        "3": 28, "high": 28, "max": 28
    }

    FSK_FREQS = [900, 1100, 1300, 1500, 1700, 1900, 2100, 2300]
    FSK_SYNC = 600
    FSK_SEP = 750
    FSK_END = 2600

    def __init__(self, password=None, color_mode=None, ecc_level="2", sign_key=None, verify_key=None, verbose=False, is_nano=False, forced_size=None, min_header=False):
        self.password = password
        self.sign_key = sign_key
        self.verify_key = verify_key
        self.verbose = verbose
        self.min_header = min_header
        self.is_nano = is_nano
        self.forced_size = self._parse_forced_size(forced_size)
        self.ecc_bytes = self._parse_ecc_level(ecc_level)
        if (self.is_nano or (self.forced_size and self.forced_size <= 5)):
            if self.forced_size and self.forced_size <= 5:
                self.ecc_bytes = min(self.ecc_bytes, 1)
            elif self.forced_size and self.forced_size <= 7:
                self.ecc_bytes = min(self.ecc_bytes, 2)
        self.rs = RSCodec(self.ecc_bytes) if self.ecc_bytes > 0 else None
        self.specified_mode = self._parse_color_mode(color_mode)

        init_mode = self.specified_mode if self.specified_mode is not None else 2
        self._set_mode(init_mode)

    def _parse_forced_size(self, size_arg):
        if not size_arg:
            return None
        size_str = str(size_arg).lower().strip()
        if "x" in size_str:
            parts = size_str.split("x")
            val = int(parts[0])
        else:
            val = int(size_str)
        return val if val % 2 != 0 else val + 1

    def _parse_ecc_level(self, level_arg):
        if level_arg is None:
            return 12
        return self.ECC_LEVELS.get(str(level_arg).lower().strip(), 12)

    def _parse_color_mode(self, mode_arg):
        if mode_arg is None:
            return None
        mode_str = str(mode_arg).lower().strip()
        if mode_str in ("0", "no", "none", "bw", "wk", "mono", "2", "b/w", "false", "off"):
            return 2
        if mode_str in ("4", "default", "min", "wkrb"):
            return 4
        if mode_str in ("8", "all", "max", "wkrbgcmy"):
            return 8
        return 4

    def _set_mode(self, num_colors):
        self.num_colors = num_colors
        if num_colors == 8:
            self.bits_per_cell = 3
        elif num_colors == 4:
            self.bits_per_cell = 2
        else:
            self.num_colors = 2
            self.bits_per_cell = 1
        self.active_palette = self.PALETTE[:self.num_colors]

    def _get_crypto(self, pwd=None):
        target_pwd = pwd if pwd else self.password
        if not target_pwd:
            return None
        key = base64.urlsafe_b64encode(hashlib.sha256(target_pwd.encode()).digest())
        return Fernet(key)

    def _mask(self, x, y):
        return (x + y) % 2 == 0

    def is_nano_grid(self, size):
        if self.is_nano:
            return True
        return size <= 7

    def _get_capacity_bytes(self, size, is_nano=None):
        nano = self.is_nano_grid(size) if is_nano is None else is_nano
        if nano:
            capacity_bits = (size * size - 6) * self.bits_per_cell
        else:
            capacity_bits = ((size * size) - (2 * size) - 1) * self.bits_per_cell
        return capacity_bits // 8

    def _data_cap_from_total_cap(self, total_cap_bytes, ecc_b=None):
        ecc = self.ecc_bytes if ecc_b is None else ecc_b
        if ecc == 0:
            return total_cap_bytes
        chunk_cap = 255
        chunk_data = 255 - ecc
        full_chunks = total_cap_bytes // chunk_cap
        rem = total_cap_bytes % chunk_cap
        rem_data = max(0, rem - ecc) if rem >= ecc else 0
        return (full_chunks * chunk_data) + rem_data

    def _calculate_required_size(self, total_raw_bytes):
        if self.forced_size:
            total_cap = self._get_capacity_bytes(self.forced_size, is_nano=self.is_nano)
            data_cap = self._data_cap_from_total_cap(total_cap)
            if data_cap < total_raw_bytes:
                raise ValueError(f"Data is too large for size {self.forced_size}x{self.forced_size} cells, can hold {data_cap} bytes maximum.")
            return self.forced_size

        size = 5 if (self.is_nano or self.min_header) else 9
        while True:
            total_cap_bytes = self._get_capacity_bytes(size, is_nano=self.is_nano)
            data_cap = self._data_cap_from_total_cap(total_cap_bytes)
            if data_cap >= total_raw_bytes:
                return size
            size += 2
            if size > 251:
                raise ValueError(f"Data is too large for a single T-Spine Code, size {size}x{size} exceeds 251x251 limit.")

    def _get_data_coordinates(self, size, is_nano=None):
        coords = []
        nano = self.is_nano_grid(size) if is_nano is None else is_nano
        if nano:
            t_cells = {(0, 0), (1, 0), (2, 0), (1, 1)}
            for y in range(size):
                for x in range(size):
                    if (x, y) in t_cells:
                        continue
                    if y == size - 1 and (x == 0 or x == size - 1):
                        continue
                    coords.append((x, y))
        else:
            for y in range(1, size):
                for x in range(size):
                    if x == size // 2:
                        continue
                    if y == size - 1 and (x == 0 or x == size - 1):
                        continue
                    coords.append((x, y))
        return coords

    def is_binary_payload(self, raw_bytes):
        try:
            raw_bytes.decode('utf-8')
            return b'\x00' in raw_bytes[:1024]
        except UnicodeDecodeError:
            return True

    def _prepare_raw_data(self, text=None, public_text=None, private_text=None):
        is_dual = public_text is not None and private_text is not None
        flags = 0

        if is_dual:
            flags |= 0x08
            pub_raw = public_text if isinstance(public_text, bytes) else public_text.encode('utf-8')
            priv_raw = private_text if isinstance(private_text, bytes) else private_text.encode('utf-8')

            cctx = zstd.ZstdCompressor(level=22)
            comp_priv = cctx.compress(priv_raw)
            if len(comp_priv) < len(priv_raw):
                priv_payload = b'\x01' + comp_priv
            else:
                priv_payload = b'\x00' + priv_raw

            crypto = self._get_crypto()
            if crypto:
                flags |= 0x02
                priv_payload = crypto.encrypt(priv_payload)

            if self.min_header:
                body = bytes([len(pub_raw) & 0xFF]) + pub_raw + bytes([len(priv_payload) & 0xFF]) + priv_payload
            else:
                body = len(pub_raw).to_bytes(4, 'big') + pub_raw + len(priv_payload).to_bytes(4, 'big') + priv_payload
        else:
            if isinstance(text, bytes):
                raw_bytes = text
            elif text is not None:
                raw_bytes = text.encode('utf-8')
            else:
                raw_bytes = b""

            if self.is_binary_payload(raw_bytes):
                flags |= 0x10

            cctx = zstd.ZstdCompressor(level=22)
            compressed_bytes = cctx.compress(raw_bytes)

            if len(compressed_bytes) < len(raw_bytes):
                flags |= 0x01
                payload = compressed_bytes
            else:
                payload = raw_bytes

            crypto = self._get_crypto()
            if crypto:
                flags |= 0x02
                payload = crypto.encrypt(payload)

            if self.min_header:
                body = bytes([len(payload) & 0xFF]) + payload
            else:
                body = len(payload).to_bytes(4, 'big') + payload

        sig_block = b""
        if self.sign_key:
            flags |= 0x04
            sig = hmac.new(self.sign_key.encode('utf-8'), body, hashlib.sha256).digest()
            sig_block = sig[:16] if self.min_header else sig

        if self.min_header:
            raw_data = bytes([flags | 0x80]) + sig_block + body
        else:
            raw_data = b"TSC" + bytes([flags]) + sig_block + body

        return raw_data, body

    def encode(self, text=None, public_text=None, private_text=None):
        raw_data, body = self._prepare_raw_data(text, public_text, private_text)
        is_dual = public_text is not None and private_text is not None
        flags = raw_data[0] & ~0x80 if self.min_header else raw_data[3]

        size = self._calculate_required_size(len(raw_data))
        is_nano = self.is_nano_grid(size)
        total_cap_bytes = self._get_capacity_bytes(size, is_nano=is_nano)
        data_cap_bytes = self._data_cap_from_total_cap(total_cap_bytes)

        padded_data = raw_data.ljust(data_cap_bytes, b'\x00')
        if self.ecc_bytes > 0:
            encoded_bytes = self.rs.encode(padded_data)
        else:
            encoded_bytes = padded_data

        if len(encoded_bytes) < total_cap_bytes:
            encoded_bytes += b'\x00' * (total_cap_bytes - len(encoded_bytes))

        header_bytes_count = (1 if self.min_header else 4) + (16 if (self.min_header and bool(flags & 0x04)) else (32 if bool(flags & 0x04) else 0)) + ((2 if self.min_header else 8) if is_dual else (1 if self.min_header else 4))
        raw_payload_count = len(body)
        ecc_start_byte = data_cap_bytes

        self.last_metadata = {
            "size": size,
            "raw_bytes": len(text) if text is not None else (len(public_text or "") + len(private_text or "")),
            "packed_bytes": len(raw_data),
            "header_bytes_count": header_bytes_count,
            "data_bytes_count": raw_payload_count,
            "ecc_start_byte": ecc_start_byte,
            "total_cap_bytes": total_cap_bytes,
            "ecc_bytes": self.ecc_bytes,
            "colors": self.num_colors,
            "bits_per_cell": self.bits_per_cell,
            "flags": flags,
            "is_dual": is_dual,
            "is_binary": bool(flags & 0x10),
            "is_signed": bool(self.sign_key),
            "is_encrypted": bool(self.password),
            "is_min_header": self.min_header,
            "is_nano": is_nano
        }

        bits = []
        for b in encoded_bytes:
            bits.extend([int(bit) for bit in format(b, '08b')])

        total_grid_bits = (size * size - 6 if is_nano else (size * size) - (2 * size) - 1) * self.bits_per_cell
        bits.extend([0] * (total_grid_bits - len(bits)))

        grid = [[0 for _ in range(size)] for _ in range(size)]

        if is_nano:
            grid[0][0] = 1
            grid[0][1] = 1
            grid[0][2] = 1
            grid[1][1] = 1
            grid[size - 1][0] = 1
            grid[size - 1][size - 1] = 0
        else:
            for i in range(size):
                grid[0][i] = 1
                grid[i][size // 2] = 1

            for c_idx in range(self.num_colors):
                if size - 1 - c_idx >= 0:
                    grid[size - 1 - c_idx][size // 2] = c_idx

            grid[size - 1][0] = 1
            grid[size - 1][size - 1] = 0

        coords = self._get_data_coordinates(size, is_nano=is_nano)
        bit_idx = 0
        mask_val = (1 << self.bits_per_cell) - 1

        for x, y in coords:
            val = 0
            for _ in range(self.bits_per_cell):
                val = (val << 1) | bits[bit_idx]
                bit_idx += 1
            if self._mask(x, y):
                val = val ^ mask_val
            grid[y][x] = val

        return grid, size

    def _unpack_payload_block(self, decoded_block):
        if len(decoded_block) < 2:
            raise ValueError(f"Corrupted data block detected, expected {len(decoded_block)} (lenght of decoded block) >= 2.")

        if decoded_block[0] & 0x80:
            is_min = True
            flags = decoded_block[0] & ~0x80
            idx = 1
        elif len(decoded_block) >= 8 and decoded_block[:3] == b"TSC":
            is_min = False
            flags = decoded_block[3]
            idx = 4
        else:
            raise ValueError("Invalid T-Spine Code header, is this a TSC code?")

        has_compression = bool(flags & 0x01)
        has_encryption = bool(flags & 0x02)
        has_signature = bool(flags & 0x04)
        is_dual = bool(flags & 0x08)
        is_binary = bool(flags & 0x10)

        if has_signature:
            sig_size = 16 if is_min else 32
            if len(decoded_block) < idx + sig_size:
                raise ValueError("Invalid or corrupted signature in TSC.")
            extracted_sig = decoded_block[idx:idx + sig_size]
            idx += sig_size
            body_start_idx = idx

            if is_dual:
                if is_min:
                    p_len = decoded_block[idx]
                    pr_pos = idx + 1 + p_len
                    pr_len = decoded_block[pr_pos]
                    body_len = 1 + p_len + 1 + pr_len
                else:
                    p_len = int.from_bytes(decoded_block[idx:idx + 4], 'big')
                    pr_pos = idx + 4 + p_len
                    pr_len = int.from_bytes(decoded_block[pr_pos:pr_pos + 4], 'big')
                    body_len = 4 + p_len + 4 + pr_len
            else:
                if is_min:
                    p_len = decoded_block[idx]
                    body_len = 1 + p_len
                else:
                    p_len = int.from_bytes(decoded_block[idx:idx + 4], 'big')
                    body_len = 4 + p_len

            body_to_verify = decoded_block[body_start_idx:body_start_idx + body_len]

            if self.verify_key:
                full_hash = hmac.new(self.verify_key.encode('utf-8'), body_to_verify, hashlib.sha256).digest()
                expected_sig = full_hash[:16] if is_min else full_hash
                if not hmac.compare_digest(expected_sig, extracted_sig):
                    raise ValueError("Signature verification FAILED, signature does not match.")
                if self.verbose:
                    print(f"{Fore.GREEN}[s] Signature verification PASSED, signature is matching.")
            elif self.verbose:
                print(f"{Fore.YELLOW}[i] Code is signed. Pass -V/--verify <signature> to verify.")

        if is_dual:
            if is_min:
                pub_len = decoded_block[idx]
                idx += 1
                pub_bytes = decoded_block[idx:idx + pub_len]
                idx += pub_len
                priv_len = decoded_block[idx]
                idx += 1
                priv_payload = decoded_block[idx:idx + priv_len]
            else:
                pub_len = int.from_bytes(decoded_block[idx:idx + 4], 'big')
                idx += 4
                pub_bytes = decoded_block[idx:idx + pub_len]
                idx += pub_len
                priv_len = int.from_bytes(decoded_block[idx:idx + 4], 'big')
                idx += 4
                priv_payload = decoded_block[idx:idx + priv_len]

            pub_text = pub_bytes.decode('utf-8', errors='replace')
            priv_text = "[Pass key via -p <key> to decrypt]"

            if has_encryption:
                crypto = self._get_crypto()
                if crypto:
                    try:
                        decrypted = crypto.decrypt(bytes(priv_payload))
                        comp_flag = decrypted[0]
                        priv_bytes = decrypted[1:]
                        if comp_flag == 1:
                            dctx = zstd.ZstdDecompressor()
                            priv_text = dctx.decompress(priv_bytes).decode('utf-8', errors='replace')
                        else:
                            priv_text = priv_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        priv_text = "[Incorrect password]"
            else:
                comp_flag = priv_payload[0]
                priv_bytes = priv_payload[1:]
                if comp_flag == 1:
                    dctx = zstd.ZstdDecompressor()
                    priv_text = dctx.decompress(priv_bytes).decode('utf-8', errors='replace')
                else:
                    priv_text = priv_bytes.decode('utf-8', errors='replace')

            return f"{Fore.GREEN}Public data:\n{Style.RESET_ALL}{pub_text}\n\n{Fore.YELLOW}Private data:\n{Style.RESET_ALL}{priv_text}"

        else:
            if is_min:
                payload_len = decoded_block[idx]
                idx += 1
            else:
                payload_len = int.from_bytes(decoded_block[idx:idx + 4], 'big')
                idx += 4

            payload = decoded_block[idx:idx + payload_len]

            if has_encryption:
                crypto = self._get_crypto()
                if not crypto:
                    raise ValueError("Data is encrypted. Provide password with -p/--password <key>.")
                payload = crypto.decrypt(bytes(payload))

            if has_compression:
                dctx = zstd.ZstdDecompressor()
                out_bytes = dctx.decompress(payload)
            else:
                out_bytes = payload

            if is_binary:
                return bytes(out_bytes)
            else:
                return out_bytes.decode('utf-8')

    def decode(self, grid, size, is_nano=None):
        nano = self.is_nano_grid(size) if is_nano is None else is_nano
        coords = self._get_data_coordinates(size, is_nano=nano)
        bits = []
        mask_val = (1 << self.bits_per_cell) - 1

        for x, y in coords:
            val = grid[y][x]
            if self._mask(x, y):
                val = val ^ mask_val
            for shift in reversed(range(self.bits_per_cell)):
                bits.append((val >> shift) & 1)

        total_cap_bytes = self._get_capacity_bytes(size, is_nano=nano)

        if nano:
            ecc_candidates = [self.ecc_bytes, 0, 1, 2, 4]
        else:
            ecc_candidates = [self.ecc_bytes, 0, 4, 12, 28]

        seen = set()
        ecc_candidates = [x for x in ecc_candidates if not (x in seen or seen.add(x))]

        last_err = None
        for ecc_b in ecc_candidates:
            if ecc_b > total_cap_bytes:
                continue
            data_cap_bytes = self._data_cap_from_total_cap(total_cap_bytes, ecc_b=ecc_b)
            if ecc_b == 0:
                encoded_len = total_cap_bytes
            else:
                chunk_cap = 255
                chunk_data = 255 - ecc_b
                full_chunks = data_cap_bytes // chunk_data
                rem = data_cap_bytes % chunk_data
                encoded_len = (full_chunks * chunk_cap) + (rem + ecc_b if rem > 0 else 0)

            trimmed_bits = bits[:encoded_len * 8]
            byte_array = bytearray()
            for i in range(0, len(trimmed_bits), 8):
                byte_chunk = trimmed_bits[i:i + 8]
                byte_array.append(int("".join(map(str, byte_chunk)), 2))

            try:
                if ecc_b == 0:
                    decoded_block = bytes(byte_array)
                else:
                    rs_dec = RSCodec(ecc_b)
                    decoded_block = rs_dec.decode(byte_array)[0]
                return self._unpack_payload_block(decoded_block)
            except ValueError as ve:
                if "Signature verification FAILED" in str(ve):
                    raise ve
                last_err = ve
            except Exception as e:
                last_err = e

        raise last_err if last_err else ValueError("Failed to decode this TSC due to an unknown reason.")

    def export_wav(self, text, filename, rate=8000, symbol_duration=0.5):
        raw_data, _ = self._prepare_raw_data(text)
        if self.ecc_bytes > 0:
            encoded_bytes = self.rs.encode(raw_data)
        else:
            encoded_bytes = raw_data

        b = self.bits_per_cell
        num_tones = 2 ** b

        bits = []
        for byte_val in encoded_bytes:
            bits.extend([int(bit) for bit in format(byte_val, '08b')])

        while len(bits) % b != 0:
            bits.append(0)

        symbols = []
        for i in range(0, len(bits), b):
            val = 0
            for k in range(b):
                val = (val << 1) | bits[i + k]
            symbols.append(val)

        samples_per_sym = int(rate * symbol_duration)
        audio_samples = []

        t_sync = np.linspace(0, 0.5, int(rate * 0.5), False)
        sync_wave = np.sin(2 * np.pi * self.FSK_SYNC * t_sync) * 0.7
        fade = np.linspace(0, 1, min(80, len(sync_wave) // 4))
        sync_wave[:len(fade)] *= fade
        sync_wave[-len(fade):] *= fade[::-1]
        audio_samples.extend(sync_wave)

        t_sym = np.linspace(0, symbol_duration, samples_per_sym, False)
        fade_sym = np.linspace(0, 1, min(120, samples_per_sym // 4))

        for c_idx in range(num_tones):
            freq = self.FSK_FREQS[c_idx]
            wave_chunk = np.sin(2 * np.pi * freq * t_sym) * 0.75
            wave_chunk[:len(fade_sym)] *= fade_sym
            wave_chunk[-len(fade_sym):] *= fade_sym[::-1]
            audio_samples.extend(wave_chunk)

        if self.ecc_bytes == 0:
            ecc_idx = 3
        elif self.ecc_bytes <= 4:
            ecc_idx = 0
        elif self.ecc_bytes <= 12:
            ecc_idx = 1
        else:
            ecc_idx = 2

        ecc_freq = self.FSK_FREQS[ecc_idx]
        ecc_chunk = np.sin(2 * np.pi * ecc_freq * t_sym) * 0.75
        ecc_chunk[:len(fade_sym)] *= fade_sym
        ecc_chunk[-len(fade_sym):] *= fade_sym[::-1]
        audio_samples.extend(ecc_chunk)

        t_sep = np.linspace(0, 0.3, int(rate * 0.3), False)
        sep_wave = np.sin(2 * np.pi * self.FSK_SEP * t_sep) * 0.7
        sep_wave[:len(fade)] *= fade
        sep_wave[-len(fade):] *= fade[::-1]
        audio_samples.extend(sep_wave)

        for sym in symbols:
            freq = self.FSK_FREQS[sym]
            wave_chunk = np.sin(2 * np.pi * freq * t_sym) * 0.75
            wave_chunk[:len(fade_sym)] *= fade_sym
            wave_chunk[-len(fade_sym):] *= fade_sym[::-1]
            audio_samples.extend(wave_chunk)

        end_wave = np.sin(2 * np.pi * self.FSK_END * t_sync) * 0.7
        end_wave[:len(fade)] *= fade
        end_wave[-len(fade):] *= fade[::-1]
        audio_samples.extend(end_wave)

        audio_arr = (np.array(audio_samples) * 32767).astype(np.int16)

        with wave.open(filename, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(rate)
            wf.writeframes(audio_arr.tobytes())

    def scan_wav(self, filename, symbol_duration=0.5):
        with wave.open(filename, 'rb') as wf:
            rate = wf.getframerate()
            n_frames = wf.getnframes()
            audio_bytes = wf.readframes(n_frames)

        samples = np.frombuffer(audio_bytes, dtype=np.int16).astype(np.float32) / 32768.0
        if len(samples) < rate * 0.5:
            raise ValueError(f"Audio file is too short to decode.")

        step = int(rate * 0.05)
        win_len = int(rate * 0.2)
        sep_idx = None

        for idx in range(0, len(samples) - win_len, step):
            chunk = samples[idx:idx + win_len]
            fft = np.abs(np.fft.rfft(chunk))
            freqs = np.fft.rfftfreq(len(chunk), 1.0 / rate)
            peak_freq = freqs[np.argmax(fft)]

            if abs(peak_freq - self.FSK_SEP) < 45:
                sep_idx = idx
                break

        if sep_idx is None:
            raise ValueError("Could not find frequency calibration separator tone in audio.")

        data_start_pos = sep_idx + int(rate * 0.3)
        sym_len = int(rate * symbol_duration)

        calib_tones = []
        curr_pos = sep_idx - sym_len
        while curr_pos >= 0:
            chunk = samples[curr_pos + int(sym_len * 0.2):curr_pos + int(sym_len * 0.8)]
            if len(chunk) < 50:
                break
            fft = np.abs(np.fft.rfft(chunk))
            freqs = np.fft.rfftfreq(len(chunk), 1.0 / rate)
            peak_freq = freqs[np.argmax(fft)]
            if abs(peak_freq - self.FSK_SYNC) < 50:
                break
            calib_tones.append(peak_freq)
            curr_pos -= sym_len

        calib_tones.reverse()
        if len(calib_tones) < 2:
            num_tones = 8
            ecc_b = 4
        else:
            ecc_freq = calib_tones[-1]
            num_calib = len(calib_tones) - 1
            if num_calib >= 8:
                num_tones = 8
            elif num_calib >= 4:
                num_tones = 4
            else:
                num_tones = 2

            ecc_dist = [abs(ecc_freq - f) for f in self.FSK_FREQS[:4]]
            ecc_idx = int(np.argmin(ecc_dist))
            if ecc_idx == 0:
                ecc_b = 4
            elif ecc_idx == 1:
                ecc_b = 12
            elif ecc_idx == 2:
                ecc_b = 28
            else:
                ecc_b = 0

        b = 3 if num_tones == 8 else (2 if num_tones == 4 else 1)
        ref_freqs = self.FSK_FREQS[:num_tones]

        extracted_symbols = []
        for idx in range(data_start_pos, len(samples) - sym_len + 1, sym_len):
            mid_start = idx + int(sym_len * 0.15)
            mid_end = idx + int(sym_len * 0.85)
            chunk = samples[mid_start:mid_end]
            fft = np.abs(np.fft.rfft(chunk))
            freqs = np.fft.rfftfreq(len(chunk), 1.0 / rate)
            peak_freq = freqs[np.argmax(fft)]

            if abs(peak_freq - self.FSK_END) < 65:
                break

            distances = [abs(peak_freq - f) for f in ref_freqs]
            best_val = int(np.argmin(distances))
            extracted_symbols.append(best_val)

        bits = []
        for s in extracted_symbols:
            for shift in reversed(range(b)):
                bits.append((s >> shift) & 1)

        byte_array = bytearray()
        for i in range(0, len(bits) - 7, 8):
            chunk_bits = bits[i:i + 8]
            byte_array.append(int("".join(map(str, chunk_bits)), 2))

        if ecc_b == 0:
            decoded_block = bytes(byte_array)
        else:
            rs_decoder = RSCodec(ecc_b)
            decoded_block = rs_decoder.decode(byte_array)[0]

        return self._unpack_payload_block(decoded_block)

    def export_image(self, grid, size, filename, mod_size=15, quiet_zone=2):
        img_size = (size + 2 * quiet_zone) * mod_size
        img = Image.new("RGB", (img_size, img_size), "white")
        draw = ImageDraw.Draw(img)
        for y in range(size):
            for x in range(size):
                val = grid[y][x]
                if val != 0:
                    color = self.PALETTE[val] if val < len(self.PALETTE) else (0, 0, 0)
                    px = (x + quiet_zone) * mod_size
                    py = (y + quiet_zone) * mod_size
                    draw.rectangle([px, py, px + mod_size - 1, py + mod_size - 1], fill=color)
        img.save(filename)

    def export_svg(self, grid, size, filename, mod_size=15, quiet_zone=2):
        img_size = (size + 2 * quiet_zone) * mod_size
        svg = [f'<svg width="{img_size}" height="{img_size}" xmlns="http://www.w3.org/2000/svg">']
        svg.append(f'<rect width="{img_size}" height="{img_size}" fill="white"/>')
        for y in range(size):
            for x in range(size):
                val = grid[y][x]
                if val != 0:
                    r, g, b = self.PALETTE[val] if val < len(self.PALETTE) else (0, 0, 0)
                    px = (x + quiet_zone) * mod_size
                    py = (y + quiet_zone) * mod_size
                    svg.append(f'<rect x="{px}" y="{py}" width="{mod_size}" height="{mod_size}" fill="rgb({r},{g},{b})"/>')
        svg.append('</svg>')
        with open(filename, "w") as f:
            f.write("\n".join(svg))

    def export_html(self, grid, size, filename, mod_size=16, quiet_zone=2):
        img_size = (size + 2 * quiet_zone) * mod_size
        svg_elems = []
        svg_elems.append(f'<rect width="{img_size}" height="{img_size}" fill="#ffffff"/>')

        is_nano = self.is_nano_grid(size)
        coords_list = self._get_data_coordinates(size, is_nano=is_nano)
        coords_set = set(coords_list)
        meta = getattr(self, "last_metadata", {})

        header_bytes = meta.get("header_bytes_count", 2 if self.min_header else 8)
        data_bytes = meta.get("data_bytes_count", 10)
        ecc_start = meta.get("ecc_start_byte", 20)
        has_ecc = self.ecc_bytes > 0

        for y in range(size):
            for x in range(size):
                val = grid[y][x]
                px = (x + quiet_zone) * mod_size
                py = (y + quiet_zone) * mod_size

                if (x, y) in coords_set:
                    c_idx = coords_list.index((x, y))
                    byte_offset = (c_idx * self.bits_per_cell) // 8
                    if byte_offset < header_bytes:
                        role = "Header / Metadata"
                    elif byte_offset < header_bytes + data_bytes:
                        role = "Data Payload"
                    elif has_ecc and byte_offset >= ecc_start:
                        role = "Error Correction Code"
                    else:
                        role = "Padding"
                elif is_nano and (x, y) in {(0, 0), (1, 0), (2, 0), (1, 1)}:
                    role = "TSC Nano T-Finder"
                elif not is_nano and y == 0:
                    role = "T-Finder Roof"
                elif not is_nano and x == size // 2:
                    if y >= size - self.num_colors:
                        col_idx = size - 1 - y
                        col_names = ["White", "Black", "Red", "Blue", "Green", "Cyan", "Magenta", "Yellow"]
                        c_name = col_names[col_idx] if col_idx < len(col_names) else str(col_idx)
                        role = f"Color Calibration ({c_name})"
                    else:
                        role = "T-Finder Spine"
                elif y == size - 1 and x == 0:
                    role = "Left Notch (Black)"
                elif y == size - 1 and x == size - 1:
                    role = "Right Notch (White)"
                else:
                    role = "T-Finder Skeleton"

                color_tuple = self.PALETTE[val] if val < len(self.PALETTE) else (0, 0, 0)
                r, g, b = color_tuple
                fill_color = f"rgb({r},{g},{b})"
                bin_repr = format(val, f'0{self.bits_per_cell}b')

                svg_elems.append(
                    f'<rect class="cell" x="{px}" y="{py}" width="{mod_size}" height="{mod_size}" '
                    f'fill="{fill_color}" data-x="{x}" data-y="{y}" data-val="{val}" data-bin="{bin_repr}" '
                    f'data-role="{role}" data-rgb="{fill_color}"/>'
                )

        svg_content = "\n".join(svg_elems)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>T-Spine Code (TSC) Inspector</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
body {{ background: #000000; color: #e2e8f0; display: flex; flex-direction: column; align-items: center; min-height: 100vh; padding: 2rem; }}
h1 {{ color: #38bdf8; font-size: 1.5rem; margin-bottom: 0.5rem; text-align: center; }}
.subtitle {{ color: #64748b; font-size: 0.85rem; margin-bottom: 2rem; }}
.wrapper {{ display: flex; gap: 2rem; flex-wrap: wrap; justify-content: center; align-items: flex-start; max-width: 1100px; width: 100%; }}
.matrix-card {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 1.5rem; display: flex; flex-direction: column; align-items: center; }}
svg {{ border: 2px solid #334155; border-radius: 4px; box-shadow: 0 0 30px rgba(56, 189, 248, 0.1); cursor: crosshair; }}
.cell {{ transition: stroke 0.1s; }}
.cell:hover {{ stroke: #38bdf8; stroke-width: 2px; }}
.panel {{ flex: 1; min-width: 320px; display: flex; flex-direction: column; gap: 1.5rem; }}
.card {{ background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 1.25rem; }}
.card h2 {{ font-size: 1rem; color: #38bdf8; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; margin-bottom: 1rem; }}
table {{ width: 100%; font-size: 0.85rem; border-collapse: collapse; }}
td {{ padding: 0.4rem 0; }}
td.label {{ color: #64748b; width: 45%; }}
td.val {{ color: #f8fafc; font-weight: bold; }}
.color-preview {{ display: inline-block; width: 12px; height: 12px; border-radius: 2px; vertical-align: middle; margin-left: 6px; border: 1px solid #475569; }}
</style>
</head>
<body>
<h1>T-Spine Code (TSC) Inspector</h1>
<p class="subtitle">Hover over cells of the TSC to inspect them.</p>
<div class="wrapper">
  <div class="matrix-card">
    <svg width="{img_size}" height="{img_size}" viewBox="0 0 {img_size} {img_size}">
      {svg_content}
    </svg>
  </div>
  <div class="panel">
    <div class="card">
      <h2>Cell Inspector</h2>
      <table>
        <tr><td class="label">Coordinates:</td><td class="val" id="ins-coord">(Hover on a cell...)</td></tr>
        <tr><td class="label">Cell Role:</td><td class="val" id="ins-role">-</td></tr>
        <tr><td class="label">Raw Value (DEC):</td><td class="val" id="ins-val">-</td></tr>
        <tr><td class="label">Raw Value (BIN):</td><td class="val" id="ins-bin">-</td></tr>
        <tr><td class="label">Color (RGB):</td><td class="val" id="ins-rgb">- <span id="ins-swatch" class="color-preview" style="display:none;"></span></td></tr>
      </table>
    </div>
    <div class="card">
      <h2>Metadata</h2>
      <table>
        <tr><td class="label">Matrix Size:</td><td class="val">{size} &times; {size} modules {'(Nano)' if is_nano else ''}</td></tr>
        <tr><td class="label">Color Mode:</td><td class="val">{meta.get('colors', self.num_colors)}-color ({meta.get('bits_per_cell', self.bits_per_cell)} bits/cell)</td></tr>
        <tr><td class="label">ECC Level:</td><td class="val">{self.ecc_bytes} parity bytes {'(Disabled)' if self.ecc_bytes == 0 else ''}</td></tr>
        <tr><td class="label">Header Type:</td><td class="val">{'Mini (2 byte)' if meta.get('is_min_header') else 'Standard (8 byte)'}</td></tr>
        <tr><td class="label">Data Packed:</td><td class="val">{meta.get('packed_bytes', '-')} bytes</td></tr>
        <tr><td class="label">Encrypted?</td><td class="val">{'Yes' if meta.get('is_encrypted') else 'No'}</td></tr>
        <tr><td class="label">Signed (HMAC)?</td><td class="val">{'Yes' if meta.get('is_signed') else 'No'}</td></tr>
        <tr><td class="label">Dual-Layer?</td><td class="val">{'Yes' if meta.get('is_dual') else 'No'}</td></tr>
        <tr><td class="label">Binary Data?</td><td class="val">{'Yes' if meta.get('is_binary') else 'No'}</td></tr>
      </table>
    </div>
  </div>
</div>
<script>
document.querySelectorAll('.cell').forEach(cell => {{
  cell.addEventListener('mouseenter', () => {{
    document.getElementById('ins-coord').textContent = `X: ${{cell.dataset.x}}, Y: ${{cell.dataset.y}}`;
    document.getElementById('ins-role').textContent = cell.dataset.role;
    document.getElementById('ins-val').textContent = cell.dataset.val;
    document.getElementById('ins-bin').textContent = cell.dataset.bin;
    document.getElementById('ins-rgb').textContent = cell.dataset.rgb;
    const swatch = document.getElementById('ins-swatch');
    swatch.style.display = 'inline-block';
    swatch.style.background = cell.dataset.rgb;
  }});
}});
</script>
</body>
</html>"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

    def print_terminal(self, grid, size):
        if size > 65:
            if self.verbose:
                print(f"{Fore.YELLOW}[i] Grid size ({size}x{size}) is too large (max 65x65) for terminal preview, see file.")
            return
        print(f"\n{Fore.YELLOW}T-Spine Code:")
        ANSI_COLORS = {
            0: "\033[47m  \033[0m",
            1: "\033[40m  \033[0m",
            2: "\033[41m  \033[0m",
            3: "\033[44m  \033[0m",
            4: "\033[42m  \033[0m",
            5: "\033[46m  \033[0m",
            6: "\033[45m  \033[0m",
            7: "\033[43m  \033[0m"
        }
        print(ANSI_COLORS[0] * (size + 2))
        for y in range(size):
            row_str = "\033[47m  \033[0m"
            for x in range(size):
                row_str += ANSI_COLORS.get(grid[y][x], ANSI_COLORS[1])
            row_str += "\033[47m  \033[0m"
            print(row_str)
        print(ANSI_COLORS[0] * (size + 2))

    def _order_points(self, pts):
        rect = np.zeros((4, 2), dtype="float32")
        s = pts.sum(axis=1)
        rect[0] = pts[np.argmin(s)]
        rect[2] = pts[np.argmax(s)]
        diff = np.diff(pts, axis=1)
        rect[1] = pts[np.argmin(diff)]
        rect[3] = pts[np.argmax(diff)]
        return rect

    def _warp_perspective(self, img, pts):
        rect = self._order_points(pts)
        (tl, tr, br, bl) = rect
        widthA = np.linalg.norm(br - bl)
        widthB = np.linalg.norm(tr - tr)
        maxWidth = max(int(widthA), int(widthB))

        heightA = np.linalg.norm(tr - br)
        heightB = np.linalg.norm(tl - bl)
        maxHeight = max(int(heightA), int(heightB))
        dim = max(maxWidth, maxHeight, 30)

        dst = np.array([
            [0, 0],
            [dim - 1, 0],
            [dim - 1, dim - 1],
            [0, dim - 1]], dtype="float32")

        M = cv2.getPerspectiveTransform(rect, dst)
        return cv2.warpPerspective(img, M, (dim, dim))

    def _get_candidate_transformations(self, crop):
        candidates = []
        variants = [crop, cv2.bitwise_not(crop)]

        is_dark_bg = (crop[:, :, 0] < 75) & (crop[:, :, 1] < 75) & (crop[:, :, 2] < 75)
        is_bright_skel = (crop[:, :, 0] > 180) & (crop[:, :, 1] > 180) & (crop[:, :, 2] > 180)

        if np.mean(is_dark_bg) > 0.15:
            dm = crop.copy()
            dm[is_dark_bg] = [255, 255, 255]
            dm[is_bright_skel] = [0, 0, 0]
            variants.append(dm)

        for v in variants:
            r0 = v
            r90 = cv2.rotate(r0, cv2.ROTATE_90_CLOCKWISE)
            r180 = cv2.rotate(r0, cv2.ROTATE_180)
            r270 = cv2.rotate(r0, cv2.ROTATE_90_COUNTERCLOCKWISE)
            f0 = cv2.flip(r0, 1)
            f90 = cv2.rotate(f0, cv2.ROTATE_90_CLOCKWISE)
            f180 = cv2.rotate(f0, cv2.ROTATE_180)
            f270 = cv2.rotate(f0, cv2.ROTATE_90_COUNTERCLOCKWISE)
            candidates.extend([r0, r90, r180, r270, f0, f90, f180, f270])

        return candidates

    def _try_decode_crop(self, candidate_img, modes_to_test):
        h, w = candidate_img.shape[:2]
        test_sizes = list(range(5, 253, 2))

        for size in test_sizes:
            cell_w, cell_h = w / size, h / size
            if cell_w < 1 or cell_h < 1:
                continue

            cx_arr = (np.arange(size) * cell_w + cell_w / 2).astype(int)
            cy_arr = (np.arange(size) * cell_h + cell_h / 2).astype(int)

            bl_r = candidate_img[cy_arr[-1], cx_arr[0], 2]
            br_r = candidate_img[cy_arr[-1], cx_arr[-1], 2]

            valid_nano = False
            t_p = [candidate_img[cy_arr[0], cx_arr[0], 2],
                   candidate_img[cy_arr[0], cx_arr[1], 2],
                   candidate_img[cy_arr[0], cx_arr[2], 2],
                   candidate_img[cy_arr[1], cx_arr[1], 2]]
            if all(r < 128 for r in t_p) and (bl_r < 128 and br_r >= 128):
                valid_nano = True

            valid_std = False
            py_roof = int(cell_h / 2)
            px_spine = int((size // 2) * cell_w + cell_w / 2)
            if np.all(candidate_img[py_roof, cx_arr, 2] < 128) and (bl_r < 128 and br_r >= 128):
                top_spine_pixels = [candidate_img[cy_arr[y], px_spine, 2] for y in range(max(1, size - 8))]
                if all(r < 128 for r in top_spine_pixels):
                    valid_std = True

            layouts_to_test = []
            if valid_nano:
                layouts_to_test.append(True)
            if valid_std:
                layouts_to_test.append(False)

            if not layouts_to_test:
                continue

            for is_nano_cand in layouts_to_test:
                for mode in modes_to_test:
                    self._set_mode(mode)
                    grid = [[0 for _ in range(size)] for _ in range(size)]

                    calib_palette = list(self.PALETTE[:self.num_colors])
                    if not is_nano_cand:
                        for c_idx in range(self.num_colors):
                            y_pos = size - 1 - c_idx
                            if y_pos < size:
                                cb, cg, cr = candidate_img[cy_arr[y_pos], cx_arr[size // 2]]
                                calib_palette[c_idx] = (int(cr), int(cg), int(cb))

                    for cy in range(size):
                        for cx in range(size):
                            b, g, r = candidate_img[cy_arr[cy], cx_arr[cx]]
                            if self.num_colors > 2:
                                distances = [math.dist((r, g, b), c) for c in calib_palette]
                                grid[cy][cx] = distances.index(min(distances))
                            else:
                                grid[cy][cx] = 1 if r < 128 else 0

                    try:
                        return self.decode(grid, size, is_nano=is_nano_cand)
                    except ValueError as ve:
                        if "signature verification FAILED" in str(ve):
                            raise ve
                    except Exception:
                        pass
        return None

    def _load_image(self, filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Could not find file: {filename}")

        if filename.lower().endswith('.svg'):
            import xml.etree.ElementTree as ET
            import re

            try:
                import cairosvg
                png_bytes = cairosvg.svg2png(url=filename)
                img = cv2.imdecode(np.frombuffer(png_bytes, np.uint8), cv2.IMREAD_COLOR)
                if img is not None:
                    return img
            except Exception:
                pass

            tree = ET.parse(filename)
            root = tree.getroot()

            w_str = re.sub(r'[^\d.]', '', str(root.attrib.get('width', '500')))
            h_str = re.sub(r'[^\d.]', '', str(root.attrib.get('height', '500')))
            w = int(float(w_str)) if w_str else 500
            h = int(float(h_str)) if h_str else 500

            img = Image.new("RGB", (w, h), "white")
            draw = ImageDraw.Draw(img)

            for elem in root.iter():
                if elem.tag.endswith('rect'):
                    rw = elem.attrib.get('width')
                    rh = elem.attrib.get('height')
                    if rw == "100%" or rh == "100%":
                        continue

                    rx = float(re.sub(r'[^\d.]', '', str(elem.attrib.get('x', 0))) or 0)
                    ry = float(re.sub(r'[^\d.]', '', str(elem.attrib.get('y', 0))) or 0)
                    rw = float(re.sub(r'[^\d.]', '', str(rw or 0)) or 0)
                    rh = float(re.sub(r'[^\d.]', '', str(rh or 0)) or 0)

                    fill = elem.attrib.get('fill', 'black')
                    try:
                        color = ImageColor.getrgb(fill)
                    except Exception:
                        color = (0, 0, 0)

                    draw.rectangle([rx, ry, rx + rw - 1, ry + rh - 1], fill=color)

            return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

        return cv2.imread(filename)

    def scan_image(self, filename):
        if filename.lower().endswith('.wav'):
            return self.scan_wav(filename)

        img = self._load_image(filename)
        if img is None:
            raise FileNotFoundError(f"Could not find file or failed to read: {filename}")

        dark_mask = cv2.inRange(img, (0, 0, 0), (135, 135, 135))
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, gray_thresh = cv2.threshold(gray, 220, 255, cv2.THRESH_BINARY_INV)

        candidates = [img]

        for mask in [dark_mask, gray_thresh]:
            x, y, w, h = cv2.boundingRect(mask)
            if w > 10 and h > 10:
                candidates.append(img[y:y + h, x:x + w])

            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            sorted_contours = sorted(contours, key=cv2.contourArea, reverse=True)[:5]

            for cnt in sorted_contours:
                cx, cy, cw, ch = cv2.boundingRect(cnt)
                if cw > 15 and ch > 15:
                    candidates.append(img[cy:cy + ch, cx:cx + cw])

                rect = cv2.minAreaRect(cnt)
                box = cv2.boxPoints(rect)
                box = np.intp(box)
                try:
                    warped = self._warp_perspective(img, box)
                    if warped.shape[0] > 15 and warped.shape[1] > 15:
                        candidates.append(warped)
                except Exception:
                    pass

        if self.specified_mode is not None:
            modes_to_test = [self.specified_mode]
        else:
            b_c, g_c, r_c = cv2.split(img)
            is_gray = np.max(np.abs(r_c.astype(int) - g_c.astype(int))) < 25 and np.max(np.abs(g_c.astype(int) - b_c.astype(int))) < 25
            if is_gray:
                modes_to_test = [2, 4, 8]
            else:
                modes_to_test = [8, 4, 2]

        for cand in candidates:
            for transformed in self._get_candidate_transformations(cand):
                try:
                    result = self._try_decode_crop(transformed, modes_to_test)
                    if result is not None:
                        return result
                except ValueError as ve:
                    if "signature verification FAILED" in str(ve):
                        raise ve

        raise ValueError("Failed to scan. Could not decode in forced/auto-detected color mode.")

def get_clipboard_text():
    try:
        for cmd in [['wl-paste'], ['xclip', '-selection', 'clipboard', '-o'], ['pbpaste']]:
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                return res.stdout.decode('utf-8')
            except Exception:
                pass
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        txt = r.clipboard_get()
        r.destroy()
        return txt
    except Exception as e:
        raise RuntimeError(f"Could not read data from clipboard: {e}")

def set_clipboard_text(text):
    try:
        for cmd in [['wl-copy'], ['xclip', '-selection', 'clipboard'], ['pbcopy']]:
            try:
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                p.communicate(text.encode('utf-8'))
                if p.returncode == 0:
                    return
            except Exception:
                pass
        import tkinter as tk
        r = tk.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
    except Exception as e:
        raise RuntimeError(f"Could not copy data to clipboard: {e}")

def set_clipboard_image(image_path):
    if not os.path.exists(image_path):
        return
    try:
        if sys.platform.startswith("linux"):
            try:
                with open(image_path, "rb") as f:
                    p = subprocess.Popen(['wl-copy', '-t', 'image/png'], stdin=f)
                    p.communicate()
                    if p.returncode == 0:
                        return
            except Exception:
                pass
            try:
                with open(image_path, "rb") as f:
                    p = subprocess.Popen(['xclip', '-selection', 'clipboard', '-t', 'image/png', '-i'], stdin=f)
                    p.communicate()
                    if p.returncode == 0:
                        return
            except Exception:
                pass
        elif sys.platform == "darwin":
            try:
                script = f'set the clipboard to (read (POSIX file "{os.path.abspath(image_path)}") as «class PNGf»)'
                subprocess.run(['osascript', '-e', script], check=True)
                return
            except Exception:
                pass
        elif sys.platform == "win32":
            try:
                import io
                import win32clipboard
                img = Image.open(image_path)
                output = io.BytesIO()
                img.convert("RGB").save(output, "BMP")
                data = output.getvalue()[14:]
                output.close()
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
                win32clipboard.CloseClipboard()
                return
            except Exception:
                pass
    except Exception as e:
        raise RuntimeError(f"Could not copy image to clipboard: {e}")

def get_clipboard_image():
    try:
        img = ImageGrab.grabclipboard()
        if isinstance(img, Image.Image):
            tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            img.convert("RGB").save(tmp.name, "PNG")
            tmp.close()
            return tmp.name
    except Exception:
        pass

    for cmd in [['wl-paste', '-t', 'image/png'], ['xclip', '-selection', 'clipboard', '-t', 'image/png', '-o']]:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            if res.stdout and len(res.stdout) > 50:
                tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
                tmp.write(res.stdout)
                tmp.close()
                return tmp.name
        except Exception:
            pass

    raise RuntimeError("Could not read image from clipboard. Did you copy one?")

def print_custom_help():
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 72}")
    print(f" {Fore.YELLOW}{Style.BRIGHT}T-Spine Code (TSC) 1.0{Style.RESET_ALL}{Fore.WHITE} | (c) 2026 T-Spine Code (TSC) by Subhrajit Sain")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'-' * 72}")
    print("      IDFCPL 1.0 License - https://github.com/SubhrajitSain/IDFCPL")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 72}\n")

    print(f"  {Fore.GREEN}{Style.BRIGHT}1. ENCODE{Style.RESET_ALL} {Fore.WHITE}(Create a T-Spine Code):")
    print(f"     {Fore.GREEN}python3 tsc.py encode {Fore.WHITE}[data / -] [options]")
    print(f"       {Fore.YELLOW}-i,  --input           <file.ext>          {Fore.WHITE}Read payload from a file (text/binary)")
    print(f"       {Fore.YELLOW}-Ci, --clip-input                          {Fore.WHITE}Read payload from clipboard")
    print(f"       {Fore.YELLOW}-o,  --output          <file.ext>          {Fore.WHITE}Output: png/svg/html/wav, - to pipe {Fore.LIGHTBLACK_EX}[default: tspine.png]")
    print(f"       {Fore.YELLOW}-Co, --clip-output                         {Fore.WHITE}Copy output image to clipboard")
    print(f"       {Fore.YELLOW}-n,  --nano                                {Fore.WHITE}Use Nano layout (smaller)")
    print(f"       {Fore.YELLOW}-z,  --size            <5x5/7x7/size>      {Fore.WHITE}Force specific grid dimensions")
    print(f"       {Fore.YELLOW}-m,  --min-header                          {Fore.WHITE}Minify TSC header to 2 bytes")
    print(f"       {Fore.YELLOW}-p,  --password        <password>          {Fore.WHITE}Encrypt with AES with given password")
    print(f"       {Fore.YELLOW}-c,  --colors          <0/no/4/min/8/max>  {Fore.WHITE}Color mode: {Fore.YELLOW}0{Fore.WHITE}-B/W, {Fore.YELLOW}4{Fore.WHITE}-WKRB, {Fore.YELLOW}8{Fore.WHITE}-WKRBGCMY {Fore.LIGHTBLACK_EX}[default: wk]")
    print(f"       {Fore.YELLOW}-e,  --eccl            <0/no/low/mid/high> {Fore.WHITE}Error correction mode {Fore.LIGHTBLACK_EX}[default: mid]")
    print(f"       {Fore.YELLOW}-s,  --sign            <secret_key>        {Fore.WHITE}Sign payload with HMAC-SHA256 key")
    print(f"       {Fore.YELLOW}-v,  --verbose                             {Fore.WHITE}Show details, don't provide -v to be quiet")
    print(f"       {Fore.YELLOW}-t,  --terminal                            {Fore.WHITE}Preview the generated TSC in the terminal\n")

    print(f"  {Fore.GREEN}{Style.BRIGHT}2. DUAL{Style.RESET_ALL} {Fore.WHITE}(Dual T-Spine Code):")
    print(f"     {Fore.GREEN}python3 tsc.py dual {Fore.WHITE}-pu <pub_data> -pr <priv_data> -p <password> [options]")
    print(f"       {Fore.YELLOW}-pu, --public          <text / -i file>    {Fore.WHITE}Public unencrypted data (text or file)")
    print(f"       {Fore.YELLOW}-pr, --private         <text / -i file>    {Fore.WHITE}Private encrypted data (text or file)")
    print(f"       {Fore.YELLOW}-n,  --nano                                {Fore.WHITE}Use Nano layout (smaller)")
    print(f"       {Fore.YELLOW}-z,  --size            <5x5/7x7/...>       {Fore.WHITE}Force specific grid dimensions")
    print(f"       {Fore.YELLOW}-m,  --min-header                          {Fore.WHITE}Minify header")
    print(f"       {Fore.YELLOW}-p,  --password        <password>          {Fore.WHITE}Password for private data")
    print(f"       {Fore.YELLOW}-o,  --output          <file.png/svg/html> {Fore.WHITE}Output file path {Fore.LIGHTBLACK_EX}[default: tspine.png]")
    print(f"       {Fore.YELLOW}-Co, --clip-output                         {Fore.WHITE}Copy generated image to clipboard\n")

    print(f"  {Fore.GREEN}{Style.BRIGHT}3. DECODE{Style.RESET_ALL} {Fore.WHITE}(Scan a PNG, SVG, or WAV TSC):")
    print(f"     {Fore.GREEN}python3 tsc.py decode {Fore.WHITE}[file.png/.svg/.wav] [options]")
    print(f"       {Fore.YELLOW}-Ci, --clip-input                          {Fore.WHITE}Decode image from clipboard")
    print(f"       {Fore.YELLOW}-o,  --output          <file.ext / ->      {Fore.WHITE}Save decoded payload to a file (req. for binary)")
    print(f"       {Fore.YELLOW}-Co, --clip-output                         {Fore.WHITE}Copy decoded text to clipboard")
    print(f"       {Fore.YELLOW}-p,  --password        <password>          {Fore.WHITE}Password if encrypted")
    print(f"       {Fore.YELLOW}-V,  --verify          <secret_key>        {Fore.WHITE}Verify HMAC-SHA256 signature with key")
    print(f"       {Fore.YELLOW}-c,  --colors          <0/no/4/min/8/max>  {Fore.WHITE}Force color mode")
    print(f"       {Fore.YELLOW}-v,  --verbose                             {Fore.WHITE}Show details\n")

    print(f"  {Fore.GREEN}{Style.BRIGHT}4. BATCH{Style.RESET_ALL} {Fore.WHITE}(Generate multiple TSCs at once from CSV):")
    print(f"     {Fore.GREEN}python3 tsc.py batch {Fore.WHITE}<file.csv> [options]")
    print(f"       {Fore.YELLOW}-d, --dir              <directory>         {Fore.WHITE}Output directory {Fore.LIGHTBLACK_EX}[default: batch_out]\n")

    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 72}")

def read_source_payload(data_arg, input_file, clip_input):
    if clip_input:
        return get_clipboard_text()
    if input_file:
        if input_file == "-":
            return sys.stdin.buffer.read()
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Could not find file: {input_file}")
        with open(input_file, "rb") as f:
            return f.read()
    if data_arg == "-":
        return sys.stdin.buffer.read()
    if data_arg is not None:
        return data_arg
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    raise ValueError("No input data provided. Use inline text/string, -i/--input, -Ci/--clip-input, or pipe via stdin (-).")

def main():
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        print_custom_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_encode = subparsers.add_parser("encode", add_help=False)
    p_encode.add_argument("data", nargs="?", default=None)
    p_encode.add_argument("-i", "--input", default=None)
    p_encode.add_argument("-Ci", "--clip-input", action="store_true")
    p_encode.add_argument("-o", "--output", default="tspine.png")
    p_encode.add_argument("-Co", "--clip-output", action="store_true")
    p_encode.add_argument("-m", "--min-header", action="store_true")
    p_encode.add_argument("-n", "--nano", action="store_true")
    p_encode.add_argument("-z", "--size", default=None)
    p_encode.add_argument("-p", "--password")
    p_encode.add_argument("-c", "--colors", nargs="?", const="4", default=None)
    p_encode.add_argument("-e", "--eccl", default="mid")
    p_encode.add_argument("-s", "--sign", default=None)
    p_encode.add_argument("-v", "--verbose", action="store_true")
    p_encode.add_argument("-t", "--terminal", action="store_true")

    p_dual = subparsers.add_parser("dual", add_help=False)
    p_dual.add_argument("-pu", "--public", required=True)
    p_dual.add_argument("-pr", "--private", required=True)
    p_dual.add_argument("-o", "--output", default="tspine.png")
    p_dual.add_argument("-Co", "--clip-output", action="store_true")
    p_dual.add_argument("-m", "--min-header", action="store_true")
    p_dual.add_argument("-n", "--nano", action="store_true")
    p_dual.add_argument("-z", "--size", default=None)
    p_dual.add_argument("-p", "--password")
    p_dual.add_argument("-c", "--colors", nargs="?", const="4", default=None)
    p_dual.add_argument("-e", "--eccl", default="mid")
    p_dual.add_argument("-s", "--sign", default=None)
    p_dual.add_argument("-v", "--verbose", action="store_true")
    p_dual.add_argument("-t", "--terminal", action="store_true")

    p_decode = subparsers.add_parser("decode", add_help=False)
    p_decode.add_argument("image", nargs="?", default=None)
    p_decode.add_argument("-Ci", "--clip-input", action="store_true")
    p_decode.add_argument("-o", "--output", default=None)
    p_decode.add_argument("-Co", "--clip-output", action="store_true")
    p_decode.add_argument("-p", "--password")
    p_decode.add_argument("-V", "--verify", default=None)
    p_decode.add_argument("-c", "--colors", nargs="?", const="4", default=None)
    p_decode.add_argument("-v", "--verbose", action="store_true")

    p_batch = subparsers.add_parser("batch", add_help=False)
    p_batch.add_argument("csv")
    p_batch.add_argument("-d", "--dir", default="batch_out")
    p_batch.add_argument("-c", "--colors", nargs="?", const="4", default=None)
    p_batch.add_argument("-e", "--eccl", default="mid")
    p_batch.add_argument("-m", "--min-header", action="store_true")
    p_batch.add_argument("-n", "--nano", action="store_true")
    p_batch.add_argument("-z", "--size", default=None)
    p_batch.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    try:
        if args.command == "encode":
            data_to_encode = read_source_payload(args.data, args.input, args.clip_input)

            ts = TSpineCode(
                password=args.password,
                color_mode=args.colors,
                ecc_level=args.eccl,
                sign_key=args.sign,
                verbose=args.verbose,
                is_nano=args.nano,
                forced_size=args.size,
                min_header=args.min_header
            )

            if args.output.endswith(".wav"):
                if args.verbose:
                    print(f"{Fore.CYAN}[*] Encoding WAV audio...")
                ts.export_wav(data_to_encode, args.output)
                if args.verbose:
                    print(f"{Fore.GREEN}[s] Success! Audio saved to {Fore.YELLOW}{args.output}")
                sys.exit(0)

            if args.verbose:
                ecc_str = "No ECC" if ts.ecc_bytes == 0 else f"{ts.ecc_bytes} bytes"
                mode_desc = f"{ts.num_colors}-color mode ({ts.bits_per_cell} bits/cell), ECC: {ecc_str}"
                print(f"{Fore.CYAN}[*] Encoding payload using {Fore.YELLOW}{mode_desc}{Fore.CYAN}...")

            grid, size = ts.encode(text=data_to_encode)

            if args.terminal:
                ts.print_terminal(grid, size)

            if args.output == "-":
                with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
                    tmp_p = tmp.name
                ts.export_image(grid, size, tmp_p)
                with open(tmp_p, "rb") as f:
                    sys.stdout.buffer.write(f.read())
                os.remove(tmp_p)
            elif args.output.endswith(".html"):
                ts.export_html(grid, size, args.output)
            elif args.output.endswith(".svg"):
                ts.export_svg(grid, size, args.output)
            else:
                ts.export_image(grid, size, args.output)

            if args.clip_output:
                if args.output.endswith(".png"):
                    set_clipboard_image(args.output)
                else:
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_img:
                        tmp_name = tmp_img.name
                    ts.export_image(grid, size, tmp_name)
                    set_clipboard_image(tmp_name)
                    if os.path.exists(tmp_name):
                        os.remove(tmp_name)

            if args.verbose:
                print(f"{Fore.GREEN}[s] Success! Saved to {Fore.YELLOW}{args.output} {Fore.WHITE}(Grid size: {size}x{size})")

        elif args.command == "dual":
            pub_data = args.public
            if pub_data.startswith("-i ") or pub_data.startswith("--input "):
                fpath = pub_data.split(maxsplit=1)[1]
                with open(fpath, "rb") as f:
                    pub_data = f.read()

            priv_data = args.private
            if priv_data.startswith("-i ") or priv_data.startswith("--input "):
                fpath = priv_data.split(maxsplit=1)[1]
                with open(fpath, "rb") as f:
                    priv_data = f.read()

            ts = TSpineCode(
                password=args.password,
                color_mode=args.colors,
                ecc_level=args.eccl,
                sign_key=args.sign,
                verbose=args.verbose,
                is_nano=args.nano,
                forced_size=args.size,
                min_header=args.min_header
            )

            if args.verbose:
                print(f"{Fore.CYAN}[*] Encoding Dual TSC (Public: {len(pub_data)} bytes, Private: {len(priv_data)} bytes)...")

            grid, size = ts.encode(public_text=pub_data, private_text=priv_data)

            if args.terminal:
                ts.print_terminal(grid, size)

            if args.output.endswith(".html"):
                ts.export_html(grid, size, args.output)
            elif args.output.endswith(".svg"):
                ts.export_svg(grid, size, args.output)
            else:
                ts.export_image(grid, size, args.output)

            if args.clip_output:
                if args.output.endswith(".png"):
                    set_clipboard_image(args.output)
                else:
                    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_img:
                        tmp_name = tmp_img.name
                    ts.export_image(grid, size, tmp_name)
                    set_clipboard_image(tmp_name)
                    if os.path.exists(tmp_name):
                        os.remove(tmp_name)

            if args.verbose:
                print(f"{Fore.GREEN}[s] Success! Saved to {Fore.YELLOW}{args.output} {Fore.WHITE}(Grid size: {size}x{size})")

        elif args.command == "decode":
            ts = TSpineCode(
                password=args.password,
                color_mode=args.colors,
                verify_key=args.verify,
                verbose=args.verbose
            )

            tmp_clip_img = None
            if args.clip_input:
                image_source = get_clipboard_image()
                tmp_clip_img = image_source
            elif args.image:
                image_source = args.image
            else:
                raise ValueError("No image provided. Specify an image/audio file path or use -Ci/--clip-input.")

            if args.verbose:
                mode_desc = f"{ts.specified_mode}-color mode" if ts.specified_mode else "auto-detect mode"
                print(f"{Fore.CYAN}[*] Scanning {image_source if not args.clip_input else 'clipboard image'} ({mode_desc})...")

            result = ts.scan_image(image_source)

            if tmp_clip_img and os.path.exists(tmp_clip_img):
                os.remove(tmp_clip_img)

            if isinstance(result, bytes):
                if args.output == "-":
                    sys.stdout.buffer.write(result)
                    sys.stdout.buffer.flush()
                elif args.output:
                    with open(args.output, "wb") as f:
                        f.write(result)
                    if args.verbose:
                        print(f"{Fore.GREEN}[s] Success! Saved to {Fore.YELLOW}{args.output}")
                else:
                    sys.stderr.write(f"{Fore.RED}[x] Error: Cannot decode binary file in terminal, use -o <file.ext> to save as file.\n")
                    sys.exit(1)
            else:
                if args.clip_output:
                    set_clipboard_text(result)

                if args.output == "-":
                    sys.stdout.write(result)
                    sys.stdout.flush()
                elif args.output:
                    with open(args.output, "w", encoding="utf-8") as f:
                        f.write(result)
                    if args.verbose:
                        print(f"{Fore.GREEN}[s] Success! Saved to {Fore.YELLOW}{args.output}")
                else:
                    if args.verbose:
                        print(f"\n{Fore.GREEN}[s] Decoded data:\n{Fore.WHITE}{result}")
                    else:
                        print(result)

        elif args.command == "batch":
            ts = TSpineCode(color_mode=args.colors, ecc_level=args.eccl, verbose=args.verbose, is_nano=args.nano, forced_size=args.size, min_header=args.min_header)
            os.makedirs(args.dir, exist_ok=True)
            with open(args.csv, "r") as f:
                reader = csv.reader(f)
                for i, row in enumerate(reader):
                    if not row:
                        continue
                    grid, size = ts.encode(text=row[0])
                    fname = f"{args.dir}/tspine_{i}.png"
                    ts.export_image(grid, size, fname)
            if args.verbose:
                print(f"{Fore.GREEN}[s] Batch complete. Images saved to {Fore.YELLOW}./{args.dir}/")

    except Exception as e:
        if getattr(args, "verbose", False):
            print(f"{Fore.RED}[x] Error: {e}")
        else:
            sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Поддельный клиент Telegram для стенда моста tgws: соединяется с АДРЕСОМ ДАТА-ЦЕНТРА.

Шлёт ровно то, что шлёт настоящее приложение, идущее в дата-центр напрямую: 64 случайных
байта обфускации, в которых ключ и вектор лежат сырыми (без секрета), метка транспорта — в
хвосте, а НОМЕРА ДЦ НЕТ (там случайные байты). Именно поэтому чужой прокси такое соединение
принять не может, а мост обязан номер вписать сам — по адресу назначения.

Дальше шлёт слово и ждёт его обратно: так проверяется, что поток идёт в обе стороны и что
байты после рукопожатия мост не тронул.
"""
import argparse, os, socket, struct, sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAGS = {"abridged": b"\xef\xef\xef\xef",
        "intermediate": b"\xee\xee\xee\xee",
        "padded": b"\xdd\xdd\xdd\xdd"}


def build_handshake(tag):
    """64 байта в том виде, в каком их строит клиент: ключ и вектор — сырые байты пакета."""
    while True:
        raw = bytearray(os.urandom(64))
        if raw[0] == 0xEF:
            continue
        if bytes(raw[:4]) in (b"HEAD", b"POST", b"GET ", b"\xee\xee\xee\xee",
                              b"\xdd\xdd\xdd\xdd", b"\x16\x03\x01\x02"):
            continue
        if raw[4:8] == b"\x00\x00\x00\x00":
            continue
        key, iv = bytes(raw[8:40]), bytes(raw[40:56])
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        ks = enc.update(bytes(64))          # гамма с начала потока
        # Хвост: метка транспорта, дальше — СЛУЧАЙНОЕ, номера ДЦ у прямого соединения нет.
        tail = bytearray(tag + os.urandom(4))
        for i in range(8):
            raw[56 + i] = tail[i] ^ ks[56 + i]
        return bytes(raw), key, iv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--tag", default="padded", choices=sorted(TAGS))
    ap.add_argument("--word", default="steer-tgws")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    hs, _, _ = build_handshake(TAGS[a.tag])
    s = socket.create_connection((a.host, a.port), timeout=a.timeout)
    s.sendall(hs)
    s.sendall(a.word.encode())
    got = b""
    while len(got) < len(a.word):
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
    s.close()
    if got != a.word.encode():
        print("НЕ ВЕРНУЛОСЬ: %r" % got)
        return 1
    print("вернулось: %s" % got.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())

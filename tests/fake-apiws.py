#!/usr/bin/env python3
"""Поддельная точка wss://kwsN.web.telegram.org/apiws для стенда моста tgws.

Проверяет ровно то, что мост обязан сделать правильно, и никак иначе не проверяется:

  1) пришёл настоящий апгрейд WebSocket на /apiws с заголовками веб-клиента;
  2) первым БИНАРНЫМ кадром пришли 64 байта рукопожатия обфускации;
  3) это рукопожатие расшифровывается СЫРЫМИ ключами из него самого (байты [8..40] —
     ключ, [40..56] — вектор), то есть мост не тронул их, — и в хвосте стоит метка
     транспорта и НОМЕР ДЦ, который мост обязан был вписать сам (у прямого соединения
     клиента его там нет).

Что увидел, пишет строкой в файл --report: `dc=<N> media=<0|1> tag=<hex>`. Дальше работает
эхом: что пришло бинарным кадром, то и отправляет обратно, — этого хватает, чтобы стенд
убедился, что поток идёт в обе стороны.
"""
import argparse, base64, hashlib, socket, struct, sys, threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ctr(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return c.update(data) + c.finalize()


def read_http(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, b""
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head.decode("latin1"), rest


def recv_frame(sock, pre=b""):
    """Один кадр WebSocket. Возвращает (opcode, payload, остаток)."""
    buf = pre
    def need(n):
        nonlocal buf
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise EOFError
            buf += chunk
    need(2)
    b0, b1 = buf[0], buf[1]
    masked = b1 & 0x80
    ln = b1 & 0x7F
    off = 2
    if ln == 126:
        need(4); ln = struct.unpack(">H", buf[2:4])[0]; off = 4
    elif ln == 127:
        need(10); ln = struct.unpack(">Q", buf[2:10])[0]; off = 10
    if masked:
        need(off + 4); mask = buf[off:off + 4]; off += 4
    need(off + ln)
    payload = bytearray(buf[off:off + ln])
    if masked:
        for i in range(ln):
            payload[i] ^= mask[i & 3]
    return b0 & 0x0F, bytes(payload), buf[off + ln:]


def send_frame(sock, payload, opcode=0x2):
    """Сервер кадры НЕ маскирует (RFC 6455 §5.1)."""
    n = len(payload)
    if n < 126:
        hdr = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    sock.sendall(hdr + payload)


def serve(sock, report):
    head, rest = read_http(sock)
    if head is None:
        return
    lines = head.split("\r\n")
    if not lines[0].startswith("GET /apiws "):
        sock.sendall(b"HTTP/1.1 404 Not Found\r\n\r\n")
        return
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    if hdrs.get("upgrade", "").lower() != "websocket" or "sec-websocket-key" not in hdrs:
        sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return
    accept = base64.b64encode(
        hashlib.sha1(hdrs["sec-websocket-key"].encode() + GUID).digest()).decode()
    sock.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                  "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                  "Sec-WebSocket-Protocol: binary\r\n"
                  f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())

    op, init, rest = recv_frame(sock, rest)
    if op != 0x2 or len(init) != 64:
        return
    plain = ctr(init[8:40], init[40:56], init)
    tag = plain[56:60]
    dc = struct.unpack("<h", plain[60:62])[0]
    with open(report, "w") as f:
        f.write("dc=%d media=%d tag=%s origin=%s proto=%s\n"
                % (abs(dc), 1 if dc < 0 else 0, tag.hex(),
                   hdrs.get("origin", "-"), hdrs.get("sec-websocket-protocol", "-")))

    while True:
        try:
            op, payload, rest = recv_frame(sock, rest)
        except (EOFError, OSError):
            return
        if op == 0x8:
            return
        if op in (0x1, 0x2):
            send_frame(sock, payload)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--report", required=True)
    a = ap.parse_args()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.bind, a.port))
    srv.listen(8)
    print("apiws: жду на %s:%d" % (a.bind, a.port), flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c, a.report), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())

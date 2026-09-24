#!/usr/bin/env python3
"""Минимальный сервер VLESS без TLS — чтобы туннель можно было проверить целиком, без узла.

Зачем. Всё, что делает tunnel.c — синтез TCP, повторная передача, раскладка по потокам, —
проверяется только на живом трафике. Пока трафик брался у настоящего узла подписки, каждая
проверка зависела от чужого сервера: он то отвечал, то нет, и «не восстановилось после
потерь» было не отличить от «узел лёг». Дважды на этом остановились.

Этот сервер закрывает зависимость. Он говорит ровно ту часть VLESS, которая нужна:

    запрос:  версия(1) UUID(16) длина_доп(1) доп команда(1) порт(2) тип_адреса(1) адрес
    ответ:   версия(1)=0 длина_доп(1)=0, дальше данные

security=none и type=tcp, то есть без Reality и без HTTP/2: проверяем цикл туннеля, а не
криптографию — её проверяют векторы в tests/crypto.c.

Куда клиент просил соединиться — НЕ ВАЖНО: адрес разбирается и выбрасывается, а в ответ
всегда идёт HTTP-ответ заданной длины. Так тест не зависит ещё и от интернета.
"""
import argparse
import os
import socket
import socketserver
import sys
import threading

ADDR_IPV4, ADDR_DOMAIN, ADDR_IPV6 = 1, 2, 3
CMD_TCP, CMD_UDP = 1, 2


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_request(sock):
    """Разобрать заголовок запроса. Возвращает (uuid, cmd, port, адрес) или None.

    Адрес — строкой (IPv4, IPv6 или имя); нужен только пересылке UDP (--udp-relay), остальные
    режимы его выбрасывают."""
    head = recv_exactly(sock, 18)           # версия + UUID + длина_доп
    if not head or head[0] != 0:
        return None
    uuid, addon_n = head[1:17], head[17]
    if addon_n and recv_exactly(sock, addon_n) is None:
        return None
    tail = recv_exactly(sock, 4)            # команда + порт + тип адреса
    if not tail:
        return None
    cmd, port, atype = tail[0], (tail[1] << 8) | tail[2], tail[3]
    if atype == ADDR_IPV4:
        need = 4
    elif atype == ADDR_IPV6:
        need = 16
    elif atype == ADDR_DOMAIN:
        ln = recv_exactly(sock, 1)
        if not ln:
            return None
        need = ln[0]
    else:
        return None
    raw = recv_exactly(sock, need)
    if raw is None:
        return None
    if atype == ADDR_IPV4:
        addr = socket.inet_ntop(socket.AF_INET, raw)
    elif atype == ADDR_IPV6:
        addr = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        addr = raw.decode("ascii", "replace")
    return uuid, cmd, port, addr


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        req = read_request(sock)
        if req is None:
            return
        uuid, cmd, port, addr = req
        if uuid != self.server.uuid:
            return                          # чужой ключ — молчим, как настоящий сервер

        if cmd == CMD_UDP:
            if self.server.udp_relay:
                self.relay_udp(sock, addr, port)
            else:
                self.serve_udp(sock)
            return

        # Порт 9 (discard) — соединение, которое ОТКРЫТО и молчит.
        #
        # Нужно, чтобы стенд умел воспроизводить главный случай слабого роутера: браузер
        # держит десятки соединений живыми между запросами (keep-alive), и цена витка цикла
        # растёт с числом таких, а не с трафиком. Без них замер показывает скорость на пустой
        # таблице — то есть ровно не то, во что упирается настоящий роутер.
        if port == 9:
            try:
                while sock.recv(65536):
                    pass
            except OSError:
                pass
            return

        # Порт 7 (echo) — ответ ТОЛЬКО после того, как дочитан запрос до перевода строки.
        #
        # Нужен стенду tests/run-tunnel-fin.sh (I-319): клиент шлёт строку и сразу FIN,
        # часто одним сегментом, и ответ обязан прийти на уже закрытую клиентом половину.
        # Обычный режим ниже отвечает, не глядя на запрос, и потерю хвоста не заметил бы.
        if port == 7:
            sock.sendall(b"\x00\x00")
            buf = b""
            try:
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if buf.endswith(b"\n"):
                    sock.sendall(b"ECHO " + buf)
                sock.shutdown(socket.SHUT_WR)
                while sock.recv(65536):
                    pass
            except OSError:
                pass
            return

        # Остаток запроса надо ВЫЧИТАТЬ, а не игнорировать, и это не аккуратность.
        # Клиент присылает за заголовком VLESS ещё и сам запрос HTTP. Закрыть соединение,
        # оставив его непрочитанным, значит заставить Linux послать RST вместо FIN — а RST
        # выбрасывает всё, что приёмник ещё не забрал из своего буфера. Стенд из-за этого
        # терял последние полтора мегабайта на каждой закачке, и выглядело это ровно как
        # «туннель обрывает передачу под конец»: полдня ушло на поиск не в том месте.
        def drain():
            try:
                while sock.recv(65536):
                    pass
            except OSError:
                pass
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()

        # Ответ VLESS, затем сразу HTTP. Отдельной записью, как это делает Xray.
        sock.sendall(b"\x00\x00")

        body_n = self.server.body_n
        head = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % body_n
        )
        sent = 0
        try:
            sock.sendall(head)
            chunk = 64 * 1024
            while sent < body_n:
                n = min(chunk, body_n - sent)
                sock.sendall(self.server.filler[:n])
                sent += n
        except Exception as e:
            # Причину печатаем ВСЕГДА. Молчаливый обрыв тут выглядит как обрыв в туннеле —
            # именно на это и ушёл один заход отладки: сервер закрывал соединение сам, а
            # разбирались с повторной передачей.
            print("fake-vless: обрыв на %d из %d байт: %r" % (sent, body_n, e),
                  file=sys.stderr, flush=True)
            return
        # Закрываем свою половину и ждём, пока клиент закроет свою: тогда уходит FIN, а не
        # RST, и всё отправленное доезжает.
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        reader.join(timeout=10)
        print("fake-vless: отдал %d байт" % sent, file=sys.stderr, flush=True)


    def serve_udp(self, sock):
        """Поток UDP (команда 2): датаграммы с двухбайтовой длиной, ЭХО обратно.

        Эхо, а не осмысленный ответ, потому что проверяется ровно перенос датаграмм:
        сохранились ли границы, дошли ли байты, и не склеились ли две в одну. Любой другой
        ответ пришлось бы сверять с содержимым, а содержимое здесь и есть проверка.

        Длина ответа берётся ЧУЖАЯ — та, что пришла: вернув свою, стенд перестал бы замечать
        как раз ту ошибку, ради которой он написан (потерянную или сдвинутую длину).
        """
        sock.sendall(b"\x00\x00")               # ответ VLESS: версия, длины доп нет
        buf = b""
        n_dg = 0
        try:
            while True:
                if len(buf) < 2:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    continue
                want = (buf[0] << 8) | buf[1]
                if len(buf) < 2 + want:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    continue
                payload = buf[2:2 + want]
                buf = buf[2 + want:]
                n_dg += 1
                # Отдаём тем же кадром. Датаграмма нулевой длины законна — её эхо тоже.
                sock.sendall(bytes([want >> 8, want & 255]) + payload)
        except OSError:
            pass
        print("fake-vless: UDP-поток закрыт, датаграмм %d" % n_dg, file=sys.stderr, flush=True)


    def relay_udp(self, sock, addr, port):
        """Поток UDP с НАСТОЯЩЕЙ пересылкой: датаграммы уходят туда, куда просил клиент, ответы
        возвращаются тем же кадром. Включается --udp-relay.

        Нужен стенду tests/run-via.sh: WireGuard внутри VLESS (выход awg с via на выход vless)
        проверяется только настоящим пиром WireGuard за сервером — эхо вернуло бы клиенту его же
        рукопожатие, и туннель не встал бы никогда."""
        sock.sendall(b"\x00\x00")
        fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
        u = socket.socket(fam, socket.SOCK_DGRAM)
        u.connect((addr, port))
        stop = threading.Event()

        def back():
            try:
                while not stop.is_set():
                    u.settimeout(1.0)
                    try:
                        d = u.recv(65535)
                    except socket.timeout:
                        continue
                    sock.sendall(bytes([len(d) >> 8, len(d) & 255]) + d)
            except OSError:
                pass
        t = threading.Thread(target=back, daemon=True)
        t.start()
        buf = b""
        n_dg = 0
        try:
            while True:
                if len(buf) >= 2 and len(buf) >= 2 + ((buf[0] << 8) | buf[1]):
                    want = (buf[0] << 8) | buf[1]
                    u.send(buf[2:2 + want])
                    buf = buf[2 + want:]
                    n_dg += 1
                    continue
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        stop.set()
        u.close()
        print("fake-vless: пересылка UDP на %s:%d закрыта, датаграмм %d" % (addr, port, n_dg),
              file=sys.stderr, flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10800)
    ap.add_argument("--uuid", required=True)
    ap.add_argument("--mb", type=int, default=20, help="сколько мегабайт отдавать в ответ")
    # Адрес слушателя — параметром, а не константой 127.0.0.1.
    #
    # Движок отвергает узел на петле как «отвечать некому» (sub.c, host_leads_nowhere):
    # панели пишут туда заглушки, и человеку полезнее внятная причина, чем ошибка TLS.
    # Стенду от этого доставалось заодно — туннель не поднимался вовсе, — поэтому сервер
    # стенда слушает на обычном адресе, который туннель считает законным узлом.
    ap.add_argument("--bind", default="127.0.0.1", help="адрес слушателя")
    ap.add_argument("--udp-relay", action="store_true",
                    help="UDP (команда 2) пересылать по адресу из запроса, а не эхом")
    a = ap.parse_args()

    srv = Server((a.bind, a.port), Handler)
    srv.uuid = bytes.fromhex(a.uuid.replace("-", ""))
    srv.body_n = a.mb * 1024 * 1024
    srv.udp_relay = a.udp_relay
    # Наполнитель фиксированный: содержимое стенду безразлично, а генерация 64 КБ на
    # каждую порцию упиралась в питон, а не в туннель.
    srv.filler = bytes(i * 131 % 251 for i in range(64 * 1024))
    print("fake-vless: %s:%d, отдаёт %d МБ" % (a.bind, a.port, a.mb), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

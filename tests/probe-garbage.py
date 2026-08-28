"""Прибор, присылающий НЕ TLS: «GET / HTTP/1.1» на порт хаба.

Отдельным файлом, а не строкой внутри tests/probe.sh: внутри shell-стенда это был бы вложенный
heredoc внутри heredoc, то есть место, где ошибаются молча.

Зачем эта проба. Порт, который на ClientHello отвечает, а на обычный HTTP-запрос молчит,
рассказывает о себе не меньше, чем порт, молчащий на всё: у настоящего сервера HTTPS «GET /»
открытым текстом вызывает ответ (у большинства — отказ TLS), а не тишину. В реализации на Go
этот случай нашёлся только стендом.

Печатает одно слово: ОТВЕТ (пришли байты), РАЗРЫВ (закрыли соединение) или ТИШИНА (не ответили
до таймаута). Ответом считаются первые два: разрыв — тоже ответ, а признак — только тишина.
"""
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 6.0

try:
    s = socket.create_connection((host, port), timeout=timeout)
except OSError as e:
    print("НЕ СОЕДИНИЛОСЬ", e)
    raise SystemExit(1)

s.sendall(b"GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n")
s.settimeout(timeout)
try:
    data = s.recv(4096)
except socket.timeout:
    print("ТИШИНА")
except OSError:
    print("РАЗРЫВ")
else:
    print("ОТВЕТ" if data else "РАЗРЫВ")
finally:
    s.close()

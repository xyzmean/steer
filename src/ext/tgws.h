/* Мост Telegram → WebSocket: перехваченное соединение с дата-центром уходит через
 * wss://kwsN.web.telegram.org/apiws. Объяснение целиком — в tgws.c и у TGWS_PORT_BASE
 * в spec.h. */
#ifndef STEER_TGWS_H
#define STEER_TGWS_H

/* Поднять мост выхода kind=tgws с именем name. Не возвращается, пока жив. */
int cmd_tgws(const char *spec, const char *name);

/* Проверить путь до Telegram целиком: TLS, апгрейд веб-сокета и настоящий обмен MTProto
 * (req_pq_multi → resPQ). 0 — дата-центр ответил. */
int cmd_tgws_probe(int dc, int media);

#endif

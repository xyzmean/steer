/* puff.h
  Copyright (C) 2002-2013 Mark Adler, all rights reserved
  version 2.3, 21 Jan 2013

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler    madler@alumni.caltech.edu
 */


/*
 * See puff.c for purpose and usage.
 */
#ifndef NIL
#  define NIL ((unsigned char *)0)      /* for no output option */
#endif

int puff(unsigned char *dest,           /* pointer to destination pointer */
         unsigned long *destlen,        /* amount of output space */
         const unsigned char *source,   /* pointer to source data pointer */
         unsigned long *sourcelen);     /* amount of input available */

/* ---- ДОПИСАНО В STEER: потоковая распаковка (см. конец puff.c) --------------------------
 *
 * Вход — сырой DEFLATE целиком в памяти; выход — кусками по запросу, с окном в 32 КБ вместо
 * буфера на весь результат. puff_stream_read отдаёт сколько распаковалось (меньше n — только
 * в конце потока), 0 — поток кончился, -1 — испорченные данные (код в err, как у puff()). */
#ifndef PUFF_STREAM_H
#define PUFF_STREAM_H
#define PUFF_WINDOW 32768u
enum { PS_HDR = 0, PS_STORED, PS_CODES, PS_DONE };
struct puff_stream {
    const unsigned char *in;
    unsigned long inlen, incnt;
    int bitbuf, bitcnt;
    int err;                        /* 0 — всё хорошо; иначе код, как у puff() */
    int phase, last;
    unsigned stored_left;
    unsigned copy_len, copy_dist;
    unsigned long wpos, total;
    unsigned long adler_a, adler_b;
    short lencnt[16], lensym[288];
    short distcnt[16], distsym[30];
    unsigned char win[PUFF_WINDOW];
};
void puff_stream_init(struct puff_stream *s, const unsigned char *src, unsigned long srclen);
long puff_stream_read(struct puff_stream *s, unsigned char *dst, unsigned long n);
/* Поток дошёл до последнего блока без ошибок. */
int puff_stream_done(const struct puff_stream *s);
/* Adler-32 распакованного — сверять с хвостом zlib-обёртки (RFC 1950). */
unsigned long puff_stream_adler(const struct puff_stream *s);
#endif

#ifndef STEER_REGISTRY_H
#define STEER_REGISTRY_H

/* 0 — раздал места, e не тронут; -1 — отказ (кончились места под метки), текст в e->msg —
 * см. правило 5, docs/architecture.md, раздел 2. Завершает процесс только вызывающий.
 * Пишет mark/table в выходы s — правило 6 (раздел 2): спека передаётся параметром. */
int registry_assign(struct spec *s, struct err *e);

#endif

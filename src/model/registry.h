#ifndef STEER_REGISTRY_H
#define STEER_REGISTRY_H

/* 0 — раздал места, e не тронут; -1 — отказ (кончились места под метки), текст в e->msg —
 * см. правило 5, docs/architecture.md, раздел 2. Завершает процесс только вызывающий. */
int registry_assign(struct err *e);

#endif

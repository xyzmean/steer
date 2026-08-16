#!/usr/bin/env python3
"""Пригоден ли workflow к запуску: выражения GitHub и разбор YAML.

Зачем отдельной проверкой. GitHub раскрывает выражения по ВСЕМУ тексту шага, включая
комментарии оболочки внутри `run:`. Пример выражения, написанный в комментарии ради
объяснения, — это не текст, а синтаксическая ошибка: «Invalid workflow file: an
expression was expected», и релиз падает ещё до первой команды. Ровно так и случилось:
комментарий объяснял, почему значение передаётся через env, и содержал пустое выражение.

Глазами это не ловится — ошибка выглядит обычным текстом среди обычного текста, а
сообщение GitHub указывает на начало блока `run:`, а не на виноватую строку. Поэтому
файл разбирается разбором, и делается это в `make test`, а не на стороне GitHub после
отправки.

Печатает найденные беды по строке на каждую; молчит и отвечает нулём, когда всё цело.
"""
import re
import sys


def check(path):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    bad = []

    # Пустое выражение: ${{ }} без содержимого. Именно оно и уронило релиз.
    for num, line in enumerate(text.split('\n'), 1):
        for m in re.finditer(r'\$\{\{(.*?)\}\}', line):
            if not m.group(1).strip():
                bad.append('строка %d: пустое выражение ${{ }}' % num)

    # Незакрытое выражение: открывающих больше, чем целых пар.
    opens = text.count('${{')
    closes = len(re.findall(r'\$\{\{.*?\}\}', text, re.S))
    if opens != closes:
        bad.append('незакрытых выражений: %d' % (opens - closes))

    # Сам YAML. Модуль есть не везде, и его отсутствие — не провал стенда: проверки выше
    # ловят тот класс ошибок, ради которого файл написан, и работают без зависимостей.
    try:
        import yaml
    except ImportError:
        pass
    else:
        try:
            yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001 — сообщение уходит человеку как есть
            bad.append('YAML не разбирается: %s' % exc)

    return bad


if __name__ == '__main__':
    problems = []
    for arg in sys.argv[1:]:
        problems += ['%s: %s' % (arg, p) for p in check(arg)]
    for p in problems:
        print(p)
    sys.exit(1 if problems else 0)

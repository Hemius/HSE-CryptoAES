from __future__ import annotations

from aes.gf256 import gf_mul, xtime


def _ensure_byte(value: int) -> int:
    """
    Ограничение значения одним байтом.

    Все промежуточные значения в AES должны оставаться
    в пределах одного байта, то есть в диапазоне 0..255.
    """
    return value & 0xFF


def rotl8(value: int, shift: int) -> int:
    """
    Выполнение циклического сдвига байта влево.

    Используется в аффинных преобразованиях
    при построении S-box и Inv-S-box.
    """
    value = _ensure_byte(value)
    shift %= 8
    return _ensure_byte((value << shift) | (value >> (8 - shift)))


def gf_inverse(value: int) -> int:
    """
    Вычисление мультипликативного обратного элемента в поле GF(2^8).
    
    При построении S-box и Inv-S-box байт рассматривается
    как элемент поля GF(2^8). Для ненулевого байта
    обратный элемент вычисляется возведением в степень 254
    по малой теореме Ферма:
     a^(2^8 - 1) = 1 -> a^(-1) = a^254
    Для 0x00 по умолчанию используется значение 0x00.
    """
    value = _ensure_byte(value)
    if value == 0:
        return 0

    result = value
    for _ in range(6):
        result = gf_mul(result, result)
        result = gf_mul(result, value)
    result = gf_mul(result, result)
    return result


def affine_transform(value: int) -> int:
    """
    Аффинное преобразование байта, используемое при построении S-box AES.

    После нахождения мультипликативного обратного элемента
    к нему применяется аффинное преобразование над GF(2),
    задающее окончательное значение S-box.
    """
    value = _ensure_byte(value)

    result = (
        value
        ^ rotl8(value, 1)
        ^ rotl8(value, 2)
        ^ rotl8(value, 3)
        ^ rotl8(value, 4)
        ^ 0x63
    )

    return _ensure_byte(result)


def inv_affine_transform(value: int) -> int:
    """
    Обратное аффинное преобразование байта, используемое при построении Inv-S-box AES.

    При построении обратной таблицы
    сначала применяется обратное аффинное преобразование,
    а затем находится мультипликативный обратный элемент в GF(2^8).

    Для AES обратное аффинное преобразование можно записать как:
        x = ROTL(y, 1) ^ ROTL(y, 3) ^ ROTL(y, 6) ^ 0x05
    """
    value = _ensure_byte(value)

    result = (
        rotl8(value, 1)
        ^ rotl8(value, 3)
        ^ rotl8(value, 6)
        ^ 0x05
    )

    return _ensure_byte(result)


def generate_s_box() -> tuple[int, ...]:
    """
    Генерация таблицы прямой подстановки S-box.

    Для каждого байта:
    1. находится мультипликативный обратный элемент в GF(2^8);
    2. к результату применяется аффинное преобразование.

    Возвращает:
        Кортеж из 256 значений S-box.
    """
    s_box = [0] * 256

    for byte in range(256):
        inverse = gf_inverse(byte)
        s_box[byte] = affine_transform(inverse)

    return tuple(s_box)


def generate_inv_s_box() -> tuple[int, ...]:
    """
    Генерация таблицы обратной подстановки Inv-S-box.

    Для каждого байта:
    1. применяется обратное аффинное преобразование;
    2. находится мультипликативный обратный элемент в GF(2^8).

    Способ эквивалентен обращению готовой таблицы S-box.
    """
    inv_s_box = [0] * 256

    for byte in range(256):
        preimage = inv_affine_transform(byte)
        inv_s_box[byte] = gf_inverse(preimage)

    return tuple(inv_s_box)


def generate_rcon(count: int = 30) -> tuple[int, ...]:
    """
    Генерация последовательности раундовых констант Rcon для AES.

    В расширении ключа AES константы Rcon применяются
    при вычислении новых слов ключевого расписания.
    Значения Rcon формируются в поле GF(2^8):
    первый ненулевой элемент равен 0x01,
    а каждый следующий получается умножением предыдущего на 0x02.

    Результат начинается с 0x00 для удобства,
    чтобы индексация совпадала со стандартной записью:
    Rcon[1] = 0x01, Rcon[2] = 0x02...

    Аргументы:
        count: количество элементов Rcon, включая начальный 0x00.

    Возвращает:
        Кортеж значений Rcon.
    """
    if count <= 0:
        raise ValueError("Количество элементов Rcon должно быть положительным.")

    if count == 1:
        return (0x00,)

    rcon = [0x00, 0x01]

    while len(rcon) < count:
        rcon.append(xtime(rcon[-1]))

    return tuple(rcon)
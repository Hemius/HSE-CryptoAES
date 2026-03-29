from __future__ import annotations


REDUCTION_BYTE = 0x1B  # Байтовая константа, используемая при приведении результата умножения
                       # по модулю неприводимого многочлена x^8 + x^4 + x^3 + x + 1


def _ensure_byte(value: int) -> int:
    """
    Ограничение значения одним байтом.
    
    AES работает с элементами поля GF(2^8),
    поэтому промежуточные вычисления приводятся к 8 битам.
    """
    return value & 0xFF


def xtime(value: int) -> int:
    """
    Умножение байта на x (на 0x02) в поле GF(2^8).

    В AES умножение выполняется по модулю неприводимого многочлена:
    x^8 + x^4 + x^3 + x + 1

    Функция является базовой операцией, которая используется в преобразовании MixColumns и
    при генерации раундовых констант Rcon в процедуре расширения ключа.
    """
    value = _ensure_byte(value)
    result = value << 1

    if value & 0x80:
        result ^= REDUCTION_BYTE

    return _ensure_byte(result)


def gf_mul(a: int, b: int) -> int:
    """
    Умножение двух байт в поле GF(2^8)
    
    Функция реализует общую операцию умножения элементов конечного поля,
    используемую в AES в преобразованиях MixColumns и InvMixColumns.
    """
    a = _ensure_byte(a)
    b = _ensure_byte(b)

    result = 0

    for _ in range(8):
        if b & 0x01:
            result ^= a

        a = xtime(a)
        b >>= 1

    return _ensure_byte(result)


def mul_by_02(value: int) -> int:
    """
    Умножение байта на 0x02 в поле GF(2^8).
    
    Функция используется в преобразовании MixColumns.
    """
    return xtime(value)


def mul_by_03(value: int) -> int:
    """
    Умножение байта на 0x03 в поле GF(2^8).

    В поле GF(2^8) умножение на 0x03 можно представить как
    умножение на 0x02 с последующим XOR с исходным байтом.

    Поскольку 0x03 = 0x02 ^ 0x01:
        value * 0x03 = (value * 0x02) ^ value
        
    Функция используется в преобразовании MixColumns.
    """
    value = _ensure_byte(value)
    return xtime(value) ^ value


def mul_by_09(value: int) -> int:
    """
    Умножение байта на 0x09 в поле GF(2^8).
    
    Функция используется в обратном преобразовании InvMixColumns.
    """
    return gf_mul(value, 0x09)


def mul_by_0b(value: int) -> int:
    """
    Умножение байта на 0x0B в поле GF(2^8).
        
    Функция используется в обратном преобразовании InvMixColumns.
    """
    return gf_mul(value, 0x0B)


def mul_by_0d(value: int) -> int:
    """
    Умножение байта на 0x0D в поле GF(2^8).
        
    Функция используется в обратном преобразовании InvMixColumns.
    """
    return gf_mul(value, 0x0D)


def mul_by_0e(value: int) -> int:
    """
    Умножение байта на 0x0E в поле GF(2^8).
        
    Функция используется в обратном преобразовании InvMixColumns.
    """
    return gf_mul(value, 0x0E)
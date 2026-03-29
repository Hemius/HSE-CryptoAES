from __future__ import annotations

from typing import TypeAlias

from aes.config import AES_VARIANTS
from aes.constants import RCON, S_BOX
from aes.errors import InvalidKeyLengthError
from aes.state import State, bytes_to_state

Word: TypeAlias = list[int]


def _ensure_byte(value: int) -> int:
    """
    Ограничивает значение одним байтом.

    В расширении ключа AES все промежуточные значения
    должны оставаться в пределах одного байта,
    так как операции выполняются над 4-байтными словами ключа.
    """
    return value & 0xFF


def validate_key_length(key: bytes, aes_bits: int) -> None:
    """
    Проверяет, что длина ключа соответствует выбранному варианту AES.

    AES-128 -> 16 байт
    AES-192 -> 24 байта
    AES-256 -> 32 байта
    """
    if aes_bits not in AES_VARIANTS:
        raise InvalidKeyLengthError(
            f"Неподдерживаемый вариант AES: {aes_bits}. "
            f"Ожидается одно из значений: 128, 192, 256."
        )

    expected_length = aes_bits // 8
    if len(key) != expected_length:
        raise InvalidKeyLengthError(
            f"Неверная длина ключа для AES-{aes_bits}: "
            f"ожидается {expected_length} байт, получено {len(key)} байт."
        )


def bytes_to_words(data: bytes) -> list[Word]:
    """
    Разбивает последовательность байтов на 4-байтные слова.

    В процедуре расширения ключа AES исходный ключ
    рассматривается как последовательность 4-байтных слов.
    Именно над такими словами выполняются операции
    RotWord, SubWord, применение Rcon и XOR.
    """
    if len(data) % 4 != 0:
        raise InvalidKeyLengthError(
            "Длина данных ключа должна делиться на 4 байта без остатка."
        )

    words: list[Word] = []
    for i in range(0, len(data), 4):
        words.append([data[i], data[i + 1], data[i + 2], data[i + 3]])

    return words


def word_to_bytes(word: Word) -> bytes:
    """
    Преобразование 4-байтного слова ключевого расписания
    в последовательность байтов.

    Используется при формировании раундовых ключей
    в виде последовательностей байтов.
    """
    if len(word) != 4:
        raise InvalidKeyLengthError("Слово должно содержать ровно 4 байта.")

    return bytes(_ensure_byte(value) for value in word)


def rot_word(word: Word) -> Word:
    """
    Выполнение циклического сдвига 4-байтного слова влево на один байт.

    Используется в процедуре расширения ключа AES перед применением SubWord и
    добавлением раундовой константы Rcon.

    Пример:
        [a0, a1, a2, a3] -> [a1, a2, a3, a0]
    """
    if len(word) != 4:
        raise InvalidKeyLengthError("Слово должно содержать ровно 4 байта.")

    return word[1:] + word[:1]


def sub_word(word: Word) -> Word:
    """
    Применение таблицы S-box к каждому байту 4-байтного слова.

    Используется в процедуре расширения ключа AES
    для нелинейного преобразования слов ключевого расписания.
    """
    if len(word) != 4:
        raise InvalidKeyLengthError("Слово должно содержать ровно 4 байта.")

    return [S_BOX[_ensure_byte(value)] for value in word]


def xor_words(left: Word, right: Word) -> Word:
    """
    Выполнение поэлементного XOR двух 4-байтных слов.

    Через XOR в AES строятся новые элементы ключевого расписания
    на основе ранее вычисленных слов.
    """
    if len(left) != 4 or len(right) != 4:
        raise InvalidKeyLengthError("Оба слова должны содержать ровно 4 байта.")

    return [_ensure_byte(a ^ b) for a, b in zip(left, right)]


def words_to_round_keys(words: list[Word]) -> list[State]:
    """
    Преобразование расширенных 4-байтных слов ключевого расписания
    в раундовые ключи AES в виде матриц состояния State.

    Каждый раундовый ключ AES имеет размер 16 байт
    и состоит из четырех 4-байтных слов.
    После группировки такой ключ переводится
    в матрицу состояния 4x4 для использования в AddRoundKey.
    """
    if len(words) % 4 != 0:
        raise InvalidKeyLengthError(
            "Расширенные слова ключа должны образовывать полные раундовые ключи "
            "(группы по 4 слова)."
        )

    round_keys: list[State] = []

    for i in range(0, len(words), 4):
        round_key_bytes = b"".join(word_to_bytes(word) for word in words[i : i + 4])
        round_keys.append(bytes_to_state(round_key_bytes))

    return round_keys


def expand_key(key: bytes, aes_bits: int) -> list[State]:
    """
    Расширение пользовательского ключа в набор раундовых ключей
    для AES-128, AES-192 или AES-256.

    В AES один исходный ключ напрямую не используется
    во всех раундах. Сначала из него строится ключевое расписание,
    содержащее начальный ключ и ключи для каждого раунда.
    Расширение выполняется с помощью операций RotWord, SubWord,
    XOR и раундовых констант Rcon.

    Возвращает:
        Список раундовых ключей, где каждый ключ
        представлен в виде матрицы состояния 4x4.

    Примечания:
        AES-128: Nk = 4, Nr = 10  -> 11 раундовых ключей
        AES-192: Nk = 6, Nr = 12  -> 13 раундовых ключей
        AES-256: Nk = 8, Nr = 14  -> 15 раундовых ключей
    """
    validate_key_length(key, aes_bits)

    params = AES_VARIANTS[aes_bits]
    nk = params.nk
    nr = params.nr
    nb = params.nb

    total_words = nb * (nr + 1)

    words = bytes_to_words(key)

    for i in range(nk, total_words):
        temp = words[i - 1][:]

        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // nk]
            temp[0] = _ensure_byte(temp[0])

        elif nk > 6 and i % nk == 4:
            # Дополнительный шаг SubWord используется только в AES-256 (Nk = 8)
            temp = sub_word(temp)

        words.append(xor_words(words[i - nk], temp))

    return words_to_round_keys(words)
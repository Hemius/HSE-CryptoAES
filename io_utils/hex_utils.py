from __future__ import annotations

from aes.config import BLOCK_SIZE
from aes.errors import InvalidIVError
from aes.key_schedule import validate_key_length


def normalize_hex_string(value: str) -> str:
    """
    Нормализация hex-строки:
    - удаление пробелов по краям;
    - удаление внутренних пробелов;
    - удаление необязательного префикса 0x.
    """
    normalized = value.strip().replace(" ", "").replace("\n", "").replace("\t", "")

    if normalized.lower().startswith("0x"):
        normalized = normalized[2:]

    return normalized


def parse_hex_bytes(value: str, field_name: str = "значение") -> bytes:
    """
    Преобразование hex-строки в последовательность байтов.
    """
    normalized = normalize_hex_string(value)

    if not normalized:
        raise ValueError(f"Поле «{field_name}» не должно быть пустым.")

    if len(normalized) % 2 != 0:
        raise ValueError(
            f"Поле «{field_name}» должно содержать четное количество hex-символов."
        )

    try:
        return bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError(f"Поле «{field_name}» не содержит корректные hex-данные.") from exc


def parse_hex_key(value: str, aes_bits: int) -> bytes:
    """
    Преобразование пользовательского ключа AES из шестнадцатеричного вида
    и проверка его длины для выбранного варианта AES.
    """
    key = parse_hex_bytes(value, field_name="ключ")
    validate_key_length(key, aes_bits)
    return key


def parse_hex_iv(value: str) -> bytes:
    """
    Преобразование вектора инициализации IV для режима CBC
    из шестнадцатеричного вида и проверка его длины.
    """
    iv = parse_hex_bytes(value, field_name="iv")

    if len(iv) != BLOCK_SIZE:
        raise InvalidIVError(
            f"IV должен иметь ровно {BLOCK_SIZE} байт "
            f"({BLOCK_SIZE * 2} hex-символов), получено {len(iv)} байт."
        )

    return iv
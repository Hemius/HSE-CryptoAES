from __future__ import annotations

from aes.config import BLOCK_SIZE
from aes.errors import InvalidBlockSizeError, InvalidPaddingError


def pad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Добавление дополнения PKCS#7 к входным данным.

    AES является блочным шифром, поэтому перед шифрованием
    длина данных должна быть кратна размеру блока.
    Если длина данных уже кратна block_size,
    добавляется еще один полный блок дополнения.
    """
    if block_size <= 0 or block_size > 255:
        raise InvalidBlockSizeError(
            f"Размер блока для PKCS#7 должен быть в диапазоне 1..255, получено {block_size}."
        )

    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size

    padding = bytes([padding_len]) * padding_len
    return data + padding


def unpad_pkcs7(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Удаление дополнения PKCS#7 из входных данных.

    После расшифрования эта функция восстанавливает исходную длину данных,
    удаляя байты дополнения PKCS#7.

    Выбрасывает InvalidPaddingError, если дополнение повреждено или некорректно.
    """
    if block_size <= 0 or block_size > 255:
        raise InvalidBlockSizeError(
            f"Размер блока для дополнения PKCS#7 должен быть в диапазоне 1..255, получено {block_size}."
        )

    if not data:
        raise InvalidPaddingError("Нельзя удалить дополнение PKCS#7 из пустых данных.")

    if len(data) % block_size != 0:
        raise InvalidPaddingError(
            "Длина входных данных должна быть кратна размеру блока для удаления дополнения PKCS#7."
        )

    padding_len = data[-1]

    if padding_len < 1 or padding_len > block_size:
        raise InvalidPaddingError(f"Некорректная длина дополнения PKCS#7: {padding_len}.")

    padding = data[-padding_len:]

    if padding != bytes([padding_len]) * padding_len:
        raise InvalidPaddingError("Некорректные байты дополнения PKCS#7.")

    return data[:-padding_len]
"""
Тестовые векторы для проверки блочного шифрования AES.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class AESBlockTestVector:
    """
    Эталонные тестовые векторы для проверки AES на одном блоке.

    Поля:
    - aes_bits: вариант AES (длина ключа);
    - key_hex: ключ в шестнадцатеричном виде;
    - plaintext_hex: исходный блок открытого текста;
    - ciphertext_hex: ожидаемый блок шифртекста.
    """
    aes_bits: int
    key_hex: str
    plaintext_hex: str
    ciphertext_hex: str


AES_BLOCK_TEST_VECTORS: tuple[AESBlockTestVector, ...] = (
    AESBlockTestVector(
        aes_bits=128,
        key_hex="000102030405060708090a0b0c0d0e0f",
        plaintext_hex="00112233445566778899aabbccddeeff",
        ciphertext_hex="69c4e0d86a7b0430d8cdb78070b4c55a",
    ),
    AESBlockTestVector(
        aes_bits=192,
        key_hex="000102030405060708090a0b0c0d0e0f1011121314151617",
        plaintext_hex="00112233445566778899aabbccddeeff",
        ciphertext_hex="dda97ca4864cdfe06eaf70a0ec0d7191",
    ),
    AESBlockTestVector(
        aes_bits=256,
        key_hex="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        plaintext_hex="00112233445566778899aabbccddeeff",
        ciphertext_hex="8ea2b7ca516745bfeafc49904b496089",
    ),
)
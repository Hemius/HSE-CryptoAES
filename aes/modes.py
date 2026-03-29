from __future__ import annotations

import secrets

from aes.block import decrypt_block, encrypt_block
from aes.config import AES_VARIANTS, BLOCK_SIZE
from aes.errors import InvalidIVError, InvalidKeyLengthError, InvalidCiphertextLengthError
from aes.key_schedule import expand_key, validate_key_length
from aes.padding import pad_pkcs7, unpad_pkcs7


def validate_aes_bits(aes_bits: int) -> None:
    """
    Проверка поддержки выбранного варианта AES.
    """
    if aes_bits not in AES_VARIANTS:
        raise InvalidKeyLengthError(
            f"Неподдерживаемый вариант AES: {aes_bits}. "
            f"Ожидается одно из значений: 128, 192, 256."
        )


def validate_iv(iv: bytes) -> None:
    """
    Проверка, что IV имеет длину ровно одного блока AES.
    """
    if len(iv) != BLOCK_SIZE:
        raise InvalidIVError(
            f"IV должен иметь ровно {BLOCK_SIZE} байт, получено {len(iv)} байт."
        )


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """
    Выполнение XOR двух последовательностей байтов одинаковой длины.

    Эта операция используется в режиме CBC:
    при шифровании блок открытого текста
    сначала XOR-ится с предыдущим блоком шифртекста
    или с вектором инициализации IV.
    """
    if len(left) != len(right):
        raise ValueError("Последовательности байтов для XOR должны иметь одинаковую длину.")

    return bytes(a ^ b for a, b in zip(left, right))


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    """
    Разбиение данных на блоки фиксированного размера.

    AES является блочным шифром, поэтому обработка данных 
    выполняется по блокам одинаковой длины.
    Перед разбиением длина данных уже должна быть кратна размеру блока.
    """
    if len(data) % block_size != 0:
        raise ValueError(
            f"Длина данных должна быть кратна {block_size}, получено {len(data)}."
        )

    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def generate_iv() -> bytes:
    """
    Генерация случайного вектора инициализации IV для режима CBC
    с использованием стандартной библиотеки Python secrets.

    В режиме CBC для первого блока открытого текста
    вместо предыдущего блока шифртекста используется IV.
    """
    return secrets.token_bytes(BLOCK_SIZE)


def encrypt_ecb(data: bytes, key: bytes, aes_bits: int) -> bytes:
    """
    Шифрование данных произвольной длины в режиме ECB
    с добавлением дополнения PKCS#7.

    В режиме ECB каждый блок шифруется независимо от остальных блоков.
    Перед шифрованием данные дополняются до длины, кратной размеру блока AES.
    """
    validate_aes_bits(aes_bits)
    validate_key_length(key, aes_bits)

    padded = pad_pkcs7(data, BLOCK_SIZE)
    blocks = split_blocks(padded, BLOCK_SIZE)
    round_keys = expand_key(key, aes_bits)

    encrypted_blocks = [
        encrypt_block(block, round_keys, aes_bits)
        for block in blocks
    ]

    return b"".join(encrypted_blocks)


def decrypt_ecb(data: bytes, key: bytes, aes_bits: int) -> bytes:
    """
    Расшифрование данных произвольной длины в режиме ECB
    и удаление дополнения PKCS#7.

    В режиме ECB каждый блок расшифровывается независимо.
    После расшифрования выполняется удаление дополнения PKCS#7.
    """
    validate_aes_bits(aes_bits)
    validate_key_length(key, aes_bits)

    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise InvalidCiphertextLengthError(
            "Длина шифртекста ECB должна быть ненулевой и кратной размеру блока AES."
        )

    blocks = split_blocks(data, BLOCK_SIZE)
    round_keys = expand_key(key, aes_bits)

    decrypted_blocks = [
        decrypt_block(block, round_keys, aes_bits)
        for block in blocks
    ]

    padded = b"".join(decrypted_blocks)
    return unpad_pkcs7(padded, BLOCK_SIZE)


def encrypt_cbc(data: bytes, key: bytes, aes_bits: int, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Шифрование данных произвольной длины в режиме CBC
    с добавлением дополнения PKCS#7.

    В режиме CBC перед шифрованием каждый блок открытого текста
    XOR-ится с предыдущим блоком шифртекста.
    Для первого блока вместо предыдущего шифртекста используется IV.

    Возвращает:
        Кортеж (iv, ciphertext), где iv — использованный вектор инициализации,
        ciphertext — результирующий шифртекст.
    """
    validate_aes_bits(aes_bits)
    validate_key_length(key, aes_bits)

    if iv is None:
        iv = generate_iv()

    validate_iv(iv)

    padded = pad_pkcs7(data, BLOCK_SIZE)
    blocks = split_blocks(padded, BLOCK_SIZE)
    round_keys = expand_key(key, aes_bits)

    encrypted_blocks: list[bytes] = []
    previous = iv

    for block in blocks:
        xored = xor_bytes(block, previous)
        cipher_block = encrypt_block(xored, round_keys, aes_bits)
        encrypted_blocks.append(cipher_block)
        previous = cipher_block

    return iv, b"".join(encrypted_blocks)


def decrypt_cbc(data: bytes, key: bytes, aes_bits: int, iv: bytes) -> bytes:
    """
    Расшифрование данных произвольной длины в режиме CBC
    и удаление дополнения PKCS#7.

    В режиме CBC после расшифрования каждого блока
    результат XOR-ится с предыдущим блоком шифртекста.
    Для первого блока вместо предыдущего шифртекста используется IV.
    """
    validate_aes_bits(aes_bits)
    validate_key_length(key, aes_bits)
    validate_iv(iv)

    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise InvalidCiphertextLengthError(
            "Длина шифртекста CBC должна быть ненулевой и кратной размеру блока AES."
        )

    blocks = split_blocks(data, BLOCK_SIZE)
    round_keys = expand_key(key, aes_bits)

    decrypted_blocks: list[bytes] = []
    previous = iv

    for block in blocks:
        decrypted = decrypt_block(block, round_keys, aes_bits)
        plain_block = xor_bytes(decrypted, previous)
        decrypted_blocks.append(plain_block)
        previous = block

    padded = b"".join(decrypted_blocks)
    return unpad_pkcs7(padded, BLOCK_SIZE)
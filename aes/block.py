from __future__ import annotations

from aes.config import AES_VARIANTS
from aes.errors import InvalidKeyLengthError
from aes.key_schedule import expand_key
from aes.state import State, bytes_to_state, state_to_bytes, validate_block, validate_state
from aes.transforms import (
    add_round_key,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    sub_bytes,
)


def validate_round_keys(round_keys: list[State], aes_bits: int) -> None:
    """
    Проверка соответствия числа раундовых ключей выбранному варианту AES.

    В AES число раундовых ключей всегда на единицу больше числа раундов,
    так как первый раундовый ключ используется в начальном преобразовании AddRoundKey
    до выполнения основных раундов шифрования.

    AES-128 -> 11 раундовых ключей
    AES-192 -> 13 раундовых ключей
    AES-256 -> 15 раундовых ключей
    """
    if aes_bits not in AES_VARIANTS:
        raise InvalidKeyLengthError(
            f"Неподдерживаемый вариант AES: {aes_bits}. "
            f"Ожидается одно из значений: 128, 192, 256."
        )

    expected_count = AES_VARIANTS[aes_bits].nr + 1

    if len(round_keys) != expected_count:
        raise InvalidKeyLengthError(
            f"Неверное количество раундовых ключей для AES-{aes_bits}: "
            f"ожидается {expected_count}, получено {len(round_keys)}."
        )

    for round_key in round_keys:
        validate_state(round_key)


def encrypt_block(block: bytes, round_keys: list[State], aes_bits: int) -> bytes:
    """
    Шифрование одного 16-байтного блока с помощью AES.

    Входной блок сначала преобразуется в матрицу состояния State.
    Затем выполняются:
    - начальное преобразование AddRoundKey;
    - основные раунды, включающие SubBytes, ShiftRows,
      MixColumns и AddRoundKey;
    - финальный раунд, в котором MixColumns не применяется.

    Аргументы:
        block: блок открытого текста длиной ровно 16 байт;
        round_keys: расширенные раундовые ключи в виде списка матриц State 4x4;
        aes_bits: вариант AES: 128, 192 или 256.

    Возвращает:
        Блок шифртекста длиной ровно 16 байт.
    """
    validate_block(block)
    validate_round_keys(round_keys, aes_bits)

    nr = AES_VARIANTS[aes_bits].nr
    state = bytes_to_state(block)

    # Начальный раунд
    add_round_key(state, round_keys[0])

    # Основные раунды
    for round_index in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    # Финальный раунд (без MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[nr])

    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: list[State], aes_bits: int) -> bytes:
    """
    Расшифрование одного 16-байтного блока с помощью AES.

    Входной блок шифртекста сначала преобразуется в матрицу состояния State.
    Затем выполняются:
    - начальное применение последнего раундового ключа через AddRoundKey;
    - основные обратные раунды, включающие InvShiftRows, InvSubBytes,
      AddRoundKey и InvMixColumns;
    - финальный обратный раунд, в котором InvMixColumns не применяется.

    Аргументы:
        block: блок шифртекста длиной ровно 16 байт;
        round_keys: расширенные раундовые ключи в виде списка матриц State 4x4;
        aes_bits: вариант AES: 128, 192 или 256.

    Возвращает:
        Блок открытого текста длиной ровно 16 байт.
    """
    validate_block(block)
    validate_round_keys(round_keys, aes_bits)

    nr = AES_VARIANTS[aes_bits].nr
    state = bytes_to_state(block)

    # Начальный обратный раунд
    add_round_key(state, round_keys[nr])

    # Основные обратные раунды
    for round_index in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    # Финальный обратный раунд (без InvMixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)


def encrypt_block_with_key(block: bytes, key: bytes, aes_bits: int) -> bytes:
    """
    Расширение пользовательского ключа и шифрование одного 16-байтного блока.

    Обертка для тестирования и простых сценариев.
    """
    round_keys = expand_key(key, aes_bits)
    return encrypt_block(block, round_keys, aes_bits)


def decrypt_block_with_key(block: bytes, key: bytes, aes_bits: int) -> bytes:
    """
    Расширение пользовательского ключа и расшифрование одного 16-байтного блока.

    Обертка для тестирования и простых сценариев.
    """
    round_keys = expand_key(key, aes_bits)
    return decrypt_block(block, round_keys, aes_bits)
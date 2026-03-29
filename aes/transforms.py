from __future__ import annotations

from aes.constants import INV_S_BOX, S_BOX
from aes.gf256 import (
    mul_by_02,
    mul_by_03,
    mul_by_09,
    mul_by_0b,
    mul_by_0d,
    mul_by_0e,
)
from aes.state import State, get_column, set_column, validate_state


def sub_bytes(state: State) -> State:
    """
    Преобразование SubBytes
    для существующей матрицы без создания копии.

    Каждый байт состояния независимо заменяется
    по таблице S-box.
    """
    validate_state(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]

    return state


def inv_sub_bytes(state: State) -> State:
    """
    Обратное преобразование SubBytes
    для существующей матрицы без создания копии.

    Каждый байт состояния заменяется
    по обратной таблице S-box.

    Используется при расшифровании
    для обращения преобразования SubBytes.
    """
    validate_state(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = INV_S_BOX[state[row][col]]

    return state


def shift_rows(state: State) -> State:
    """
    Преобразование ShiftRows
    для существующей матрицы без создания копии.

    Строки матрицы состояния циклически сдвигаются влево:
    строка 0 не сдвигается,
    строка 1 сдвигается на 1 байт,
    строка 2 — на 2 байта,
    строка 3 — на 3 байта.
    """
    validate_state(state)

    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]

    return state


def inv_shift_rows(state: State) -> State:
    """
    Выполняет обратное преобразование ShiftRows
    для существующей матрицы без создания копии.

    Строки матрицы состояния циклически сдвигаются вправо:
    строка 0 не сдвигается,
    строка 1 сдвигается на 1 байт,
    строка 2 — на 2 байта,
    строка 3 — на 3 байта.

    Используется при расшифровании
    для обращения преобразования ShiftRows.
    """
    validate_state(state)

    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]

    return state


def mix_columns(state: State) -> State:
    """
    Преобразование MixColumns
    для существующей матрицы без создания копии.

    Каждый столбец состояния рассматривается отдельно
    и умножается на фиксированную матрицу AES над GF(2^8):

        [02 03 01 01]
        [01 02 03 01]
        [01 01 02 03]
        [03 01 01 02]
    """
    validate_state(state)

    for col in range(4):
        s0, s1, s2, s3 = get_column(state, col)

        mixed = [
            mul_by_02(s0) ^ mul_by_03(s1) ^ s2 ^ s3,
            s0 ^ mul_by_02(s1) ^ mul_by_03(s2) ^ s3,
            s0 ^ s1 ^ mul_by_02(s2) ^ mul_by_03(s3),
            mul_by_03(s0) ^ s1 ^ s2 ^ mul_by_02(s3),
        ]

        set_column(state, col, mixed)

    return state


def inv_mix_columns(state: State) -> State:
    """
    Обратное преобразование MixColumns
    для существующей матрицы без создания копии.

    Каждый столбец состояния умножается
    на обратную матрицу AES над GF(2^8):

        [0e 0b 0d 09]
        [09 0e 0b 0d]
        [0d 09 0e 0b]
        [0b 0d 09 0e]

    Используется при расшифровании
    для обращения преобразования MixColumns.
    """
    validate_state(state)

    for col in range(4):
        s0, s1, s2, s3 = get_column(state, col)

        mixed = [
            mul_by_0e(s0) ^ mul_by_0b(s1) ^ mul_by_0d(s2) ^ mul_by_09(s3),
            mul_by_09(s0) ^ mul_by_0e(s1) ^ mul_by_0b(s2) ^ mul_by_0d(s3),
            mul_by_0d(s0) ^ mul_by_09(s1) ^ mul_by_0e(s2) ^ mul_by_0b(s3),
            mul_by_0b(s0) ^ mul_by_0d(s1) ^ mul_by_09(s2) ^ mul_by_0e(s3),
        ]

        set_column(state, col, mixed)

    return state


def add_round_key(state: State, round_key: State) -> State:
    """
    Преобразование AddRoundKey
    для существующей матрицы без создания копии.

    Каждый байт состояния поэлементно XOR-ится
    с соответствующим байтом раундового ключа.

    Преобразование вводит в состояние
    влияние текущего раундового ключа.
    Раундовый ключ должен иметь ту же форму 4x4,
    что и матрица состояния.
    """
    validate_state(state)
    validate_state(round_key)

    for row in range(4):
        for col in range(4):
            state[row][col] ^= round_key[row][col]

    return state
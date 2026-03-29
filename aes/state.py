from __future__ import annotations
from typing import TypeAlias
from aes.config import BLOCK_SIZE
from aes.errors import InvalidBlockSizeError

State: TypeAlias = list[list[int]]


def _ensure_byte(value: int) -> int:
    """
    Ограничение значений одним байтом.
    
    В AES элементы состояния представляются байтами,
    поэтому промежуточные значения приводятся к диапазону 0..255.
    """
    return value & 0xFF


def validate_block(block: bytes) -> None:
    """
    Проверка, что входной блок имеет ровно 16 байт.

    В AES размер блока фиксирован и составляет 128 бит (16 байт),
    для всех вариантов алгоритма.
    """
    if len(block) != BLOCK_SIZE:
        raise InvalidBlockSizeError(
            f"Блок AES должен иметь ровно {BLOCK_SIZE} байт, получено {len(block)} байт."
        )


def validate_state(state: State) -> None:
    """
    Проверка, что состояние представляет собой матрицу 4x4 из байтов.

    Блок данных представляется в AES в виде такой матрицы.
    Над этой матрицей выполняются основные преобразования алгоритма.
    """
    if len(state) != 4:
        raise InvalidBlockSizeError("Состояние должно содержать ровно 4 строки.")

    for row in state:
        if len(row) != 4:
            raise InvalidBlockSizeError(
                "Каждая строка состояния должна содержать ровно 4 байта."
            )

        for value in row:
            if not isinstance(value, int):
                raise InvalidBlockSizeError("Значения состояния должны быть целыми числами.")
            if not 0 <= value <= 0xFF:
                raise InvalidBlockSizeError(
                    "Значения состояния должны находиться в диапазоне 0..255."
                )


def bytes_to_state(block: bytes) -> State:
    """
    Преобразование 16-байтного блока в матрицу состояния 4x4.
    
    В AES входной блок представляется в виде матрицы состояния State,
    над которой затем выполняются преобразования SubBytes, ShiftRows,
    MixColumns и AddRoundKey.

    В AES состояние заполняется по столбцам:
        state[row][col] = block[row + 4 * col]

    Пример:
        block = b0 b1 b2 b3 b4 b5 ... b15

        state =
        [
            [b0,  b4,  b8,  b12],
            [b1,  b5,  b9,  b13],
            [b2,  b6,  b10, b14],
            [b3,  b7,  b11, b15],
        ]
    """
    validate_block(block)

    state: State = [[0] * 4 for _ in range(4)]

    for col in range(4):
        for row in range(4):
            state[row][col] = block[row + 4 * col]

    return state


def state_to_bytes(state: State) -> bytes:
    """
    Преобразование матрицы состояния AES 4x4 обратно в 16-байтный блок.

    Развертывание выполняется по столбцам:
        block[row + 4 * col] = state[row][col]
        
    Операция является обратной по отношению к bytes_to_state()
    и используется после завершения преобразований
    для получения линейного представления выходного блока.
    """
    validate_state(state)

    output = bytearray(BLOCK_SIZE)

    for col in range(4):
        for row in range(4):
            output[row + 4 * col] = _ensure_byte(state[row][col])

    return bytes(output)


def copy_state(state: State) -> State:
    """
    Создание копии матрицы состояния.
    
    Используется как вспомогательная операция,
    когда требуется работать с копией состояния,
    не изменяя исходную матрицу.
    """
    validate_state(state)
    return [row[:] for row in state]


def get_column(state: State, col: int) -> list[int]:
    """
    Возвращает один столбец состояния в виде списка из 4 байтов.
    
    Столбцы состояния важны для преобразований MixColumns и InvMixColumns,
    которые выполняются отдельно для каждого столбца матрицы State. 
    """
    validate_state(state)

    if not 0 <= col < 4:
        raise IndexError("Индекс столбца должен находиться в диапазоне 0..3.")

    return [state[row][col] for row in range(4)]


def set_column(state: State, col: int, values: list[int]) -> None:
    """
    Замена одного столбца состояния четырьмя байтовыми значениями.
    
    Используется при преобразованиях, которые изменяют состояние
    по столбцам, например в MixColumns и InvMixColumns.
    """
    validate_state(state)

    if not 0 <= col < 4:
        raise IndexError("Индекс столбца должен находиться в диапазоне 0..3.")

    if len(values) != 4:
        raise InvalidBlockSizeError("Столбец состояния должен содержать ровно 4 значения.")

    for row in range(4):
        state[row][col] = _ensure_byte(values[row])
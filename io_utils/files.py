from __future__ import annotations

from pathlib import Path

from aes.config import BLOCK_SIZE
from aes.errors import InvalidIVError


def read_binary_file(path: str | Path) -> bytes:
    """
    Считывание файла в бинарном режиме.
    """
    file_path = Path(path)
    return file_path.read_bytes()


def write_binary_file(path: str | Path, data: bytes) -> None:
    """
    Запись данных в файл в бинарном режиме.
    """
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(data)


def read_text_file(path: str | Path) -> str:
    """
    Считывание файла в текстовом режиме.

    Используется для чтения ключа из файла.
    """
    file_path = Path(path)
    return file_path.read_text(encoding="utf-8")


def prepend_iv(iv: bytes, ciphertext: bytes) -> bytes:
    """
    Сохранение результатов CBC в формате IV + шифртекст.
    """
    if len(iv) != BLOCK_SIZE:
        raise InvalidIVError(
            f"IV должен иметь ровно {BLOCK_SIZE} байт, получено {len(iv)} байт."
        )

    return iv + ciphertext


def extract_iv(data: bytes) -> tuple[bytes, bytes]:
    """
    Извлечение IV и шифртекста из данных, сохраненных как IV + шифртекст.
    """
    if len(data) < BLOCK_SIZE:
        raise InvalidIVError(
            f"Входные данные слишком короткие, чтобы содержать IV длиной {BLOCK_SIZE} байт."
        )

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    return iv, ciphertext
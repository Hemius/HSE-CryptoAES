from __future__ import annotations

import unittest

from aes.config import BLOCK_SIZE
from aes.errors import InvalidPaddingError
from aes.padding import pad_pkcs7, unpad_pkcs7


class TestPKCS7Padding(unittest.TestCase):
    """
    Тесты для PKCS#7 дополнения.
    """

    def test_pad_and_unpad_short_data(self) -> None:
        """
        Проверка корректности добавления и удаления PKCS#7 дополнения
        для коротких входных данных.
        """
        data = b"hello"
        padded = pad_pkcs7(data)

        self.assertEqual(len(padded) % BLOCK_SIZE, 0)
        self.assertEqual(unpad_pkcs7(padded), data)

    def test_pad_and_unpad_exact_block(self) -> None:
        """
        Проверка добавления полного блока дополнения для
        данных длиной ровно один блок.
        """
        data = b"A" * BLOCK_SIZE
        padded = pad_pkcs7(data)

        self.assertEqual(len(padded), BLOCK_SIZE * 2)
        self.assertEqual(padded[-1], BLOCK_SIZE)
        self.assertEqual(unpad_pkcs7(padded), data)

    def test_pad_and_unpad_empty_data(self) -> None:
        """
        Проверка работы дополнения для пустых данных.
        """
        data = b""
        padded = pad_pkcs7(data)

        self.assertEqual(len(padded), BLOCK_SIZE)
        self.assertEqual(unpad_pkcs7(padded), data)

    def test_unpad_empty_data_raises_error(self) -> None:
        """
        Проверка, что удаление дополнения из пустых данных вызывает ошибку.
        """
        with self.assertRaises(InvalidPaddingError):
            unpad_pkcs7(b"")

    def test_unpad_non_multiple_length_raises_error(self) -> None:
        """
        Проверка, что данные некратной длины вызывают ошибку при удалении дополнения.
        """
        with self.assertRaises(InvalidPaddingError):
            unpad_pkcs7(b"12345")

    def test_unpad_invalid_padding_length_raises_error(self) -> None:
        """
        Проверка, что некорректная длина дополнения вызывает ошибку.
        """
        invalid = b"A" * 15 + b"\x00"

        with self.assertRaises(InvalidPaddingError):
            unpad_pkcs7(invalid)

    def test_unpad_invalid_padding_bytes_raises_error(self) -> None:
        """
        Проверка, что поврежденные байты PKCS#7 дополнения вызывают ошибку.
        """
        valid_padded = pad_pkcs7(b"test")
        invalid_padded = valid_padded[:-1] + b"\x05"

        with self.assertRaises(InvalidPaddingError):
            unpad_pkcs7(invalid_padded)


if __name__ == "__main__":
    unittest.main()
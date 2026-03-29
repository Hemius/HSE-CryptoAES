from __future__ import annotations

import unittest

from aes.config import BLOCK_SIZE
from aes.modes import decrypt_cbc, decrypt_ecb, encrypt_cbc, encrypt_ecb


class TestAESModes(unittest.TestCase):
    """
    Тесты для проверки режимов работы AES: ECB и CBC.
    """

    AES_KEYS = {
        128: bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        192: bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        256: bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    }

    FIXED_IV = bytes.fromhex("00112233445566778899aabbccddeeff")

    TEST_DATA_SET = (
        b"",
        b"A",
        b"hello",
        b"1234567890abcdef",  # ровно 16 байт
        b"1234567890abcdefX",  # 17 байт
        b"AES test data for ECB and CBC modes.",
        bytes(range(32)),
        bytes(range(100)),
    )

    def test_ecb_encrypt_decrypt_roundtrip(self) -> None:
        """
        Проверка корректности шифрования и последующего расшифрования
        в режиме ECB для всех вариантов AES и различных входных данных.
        """
        for aes_bits, key in self.AES_KEYS.items():
            for data in self.TEST_DATA_SET:
                with self.subTest(mode="ECB", aes_bits=aes_bits, data_len=len(data)):
                    ciphertext = encrypt_ecb(data, key, aes_bits)
                    plaintext = decrypt_ecb(ciphertext, key, aes_bits)

                    self.assertEqual(plaintext, data)
                    self.assertEqual(len(ciphertext) % BLOCK_SIZE, 0)

    def test_cbc_encrypt_decrypt_roundtrip_with_fixed_iv(self) -> None:
        """
        Проверка корректности шифрования и последующего расшифрования в режиме
        CBC с фиксированным IV для всех вариантов AES и различных входных данных.
        """
        for aes_bits, key in self.AES_KEYS.items():
            for data in self.TEST_DATA_SET:
                with self.subTest(mode="CBC", aes_bits=aes_bits, data_len=len(data)):
                    iv, ciphertext = encrypt_cbc(data, key, aes_bits, iv=self.FIXED_IV)
                    plaintext = decrypt_cbc(ciphertext, key, aes_bits, iv)

                    self.assertEqual(iv, self.FIXED_IV)
                    self.assertEqual(plaintext, data)
                    self.assertEqual(len(ciphertext) % BLOCK_SIZE, 0)

    def test_cbc_generates_iv_when_not_provided(self) -> None:
        """
        Проверка автоматической генерации вектора инициализации
        при отсутствии переданного IV.
        """
        data = b"example data for cbc"
        key = self.AES_KEYS[256]

        iv, ciphertext = encrypt_cbc(data, key, 256)

        self.assertEqual(len(iv), BLOCK_SIZE)
        self.assertEqual(len(ciphertext) % BLOCK_SIZE, 0)

        plaintext = decrypt_cbc(ciphertext, key, 256, iv)
        self.assertEqual(plaintext, data)

    def test_ecb_same_plaintext_blocks_produce_same_ciphertext_blocks(self) -> None:
        """
        Проверка свойства режима ECB:
        одинаковые блоки открытого текста дают одинаковые блоки шифртекста.
        """
        key = self.AES_KEYS[128]
        data = b"A" * 16 + b"A" * 16

        ciphertext = encrypt_ecb(data, key, 128)

        first_block = ciphertext[:BLOCK_SIZE]
        second_block = ciphertext[BLOCK_SIZE:BLOCK_SIZE * 2]

        self.assertEqual(first_block, second_block)

    def test_cbc_same_plaintext_blocks_produce_different_ciphertext_blocks(self) -> None:
        """
        Проверка свойства режима CBC:
        одинаковые блоки открытого текста при одном и том же ключе
        обычно преобразуются в разные блоки шифртекста.
        """
        key = self.AES_KEYS[128]
        data = b"A" * 16 + b"A" * 16

        iv, ciphertext = encrypt_cbc(data, key, 128, iv=self.FIXED_IV)

        first_block = ciphertext[:BLOCK_SIZE]
        second_block = ciphertext[BLOCK_SIZE:BLOCK_SIZE * 2]

        self.assertNotEqual(first_block, second_block)
        self.assertEqual(len(iv), BLOCK_SIZE)


if __name__ == "__main__":
    unittest.main()
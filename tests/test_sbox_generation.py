from __future__ import annotations

import unittest

from aes.constants import INV_S_BOX, RCON, S_BOX
from aes.sbox_math import generate_inv_s_box, generate_rcon, generate_s_box


class TestSBoxGeneration(unittest.TestCase):
    """
    Тесты для алгоритмического построения S-box, Inv-S-box и Rcon.
    """

    def test_generate_s_box_matches_reference(self) -> None:
        """
        Проверка совпадения сгенерированной таблицы S-box
        с эталонной таблицей AES.
        """
        self.assertEqual(generate_s_box(), S_BOX)

    def test_generate_inv_s_box_matches_reference(self) -> None:
        """
        Проверка совпадения сгенерированной таблицы Inv-S-box
        с эталонной таблицей AES.
        """
        self.assertEqual(generate_inv_s_box(), INV_S_BOX)

    def test_generate_rcon_matches_reference(self) -> None:
        """
        Проверка совпадения сгенерированной последовательности Rcon
        с эталонной последовательностью AES.
        """
        self.assertEqual(generate_rcon(len(RCON)), RCON)

    def test_inverse_relationship(self) -> None:
        """
        Проверка, что S-box и Inv-S-box
        являются взаимно обратными отображениями.
        """
        s_box = generate_s_box()
        inv_s_box = generate_inv_s_box()

        for byte in range(256):
            substituted = s_box[byte]
            restored = inv_s_box[substituted]
            self.assertEqual(restored, byte)

            inverse_substituted = inv_s_box[byte]
            inverse_restored = s_box[inverse_substituted]
            self.assertEqual(inverse_restored, byte)


if __name__ == "__main__":
    unittest.main()
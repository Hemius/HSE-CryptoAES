from __future__ import annotations

from aes.block import decrypt_block, encrypt_block
from aes.key_schedule import expand_key
from tests.vectors import AES_BLOCK_TEST_VECTORS


def run_block_vector_checks() -> None:
    """
    Проверка шифрования и расшифрования одного блока AES
    по эталонным тестовым векторам.
    """
    print("Проверка AES на уровне одного 16-байтного блока")
    print("=" * 60)

    total = 0
    passed = 0

    for vector in AES_BLOCK_TEST_VECTORS:
        total += 1

        key = bytes.fromhex(vector.key_hex)
        plaintext = bytes.fromhex(vector.plaintext_hex)
        expected_ciphertext = bytes.fromhex(vector.ciphertext_hex)

        round_keys = expand_key(key, vector.aes_bits)

        actual_ciphertext = encrypt_block(plaintext, round_keys, vector.aes_bits)
        restored_plaintext = decrypt_block(actual_ciphertext, round_keys, vector.aes_bits)

        encrypt_ok = actual_ciphertext == expected_ciphertext
        decrypt_ok = restored_plaintext == plaintext

        status = "УСПЕШНО" if encrypt_ok and decrypt_ok else "ОШИБКА"

        print(f"AES-{vector.aes_bits}: {status}")
        print(f"  Ключ                 : {vector.key_hex}")
        print(f"  Открытый текст       : {vector.plaintext_hex}")
        print(f"  Ожидаемый шифртекст  : {vector.ciphertext_hex}")
        print(f"  Фактический шифртекст: {actual_ciphertext.hex()}")
        print(f"  Восстановленный текст: {restored_plaintext.hex()}")
        print()

        if encrypt_ok and decrypt_ok:
            passed += 1

    print("=" * 60)
    print(f"Пройдено тестов: {passed}/{total}")

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    run_block_vector_checks()
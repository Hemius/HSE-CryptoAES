from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aes.errors import AESException
from aes.modes import decrypt_cbc, decrypt_ecb, encrypt_cbc, encrypt_ecb
from io_utils.files import extract_iv, prepend_iv, read_binary_file, write_binary_file, read_text_file
from io_utils.hex_utils import parse_hex_iv, parse_hex_key


def build_parser() -> argparse.ArgumentParser:
    """
    Создание парсера аргументов командной строки.
    """
    parser = argparse.ArgumentParser(
        description="Программа шифрования и расшифрования файлов AES."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Зашифровать файл.",
    )
    add_common_arguments(encrypt_parser, include_iv=True)

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Расшифровать файл.",
    )
    add_common_arguments(decrypt_parser, include_iv=True)

    return parser


def add_common_arguments(
    parser: argparse.ArgumentParser,
    include_iv: bool = False,
) -> None:
    """
    Добавление общих аргументов командной строки
    для команд шифрования и расшифрования.
    """
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        help="Путь к исходному файлу.",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=True,
        help="Путь к файлу вывода.",
    )
    parser.add_argument(
        "--mode",
        "-m",
        required=True,
        choices=("ecb", "cbc"),
        help="Режим работы: ecb или cbc.",
    )
    parser.add_argument(
        "--aes",
        required=True,
        type=int,
        choices=(128, 192, 256),
        help="Вариант AES: 128, 192 или 256 бит.",
    )

    key_group = parser.add_mutually_exclusive_group(required=True)

    key_group.add_argument(
        "--key",
        "-k",
        help="Ключ AES в шестнадцатеричном формате.",
    )
    key_group.add_argument(
        "--key-file",
        help="Путь к файлу с ключом AES в шестнадцатеричном формате.",
    )

    if include_iv:
        parser.add_argument(
            "--iv",
            help=(
                "IV в шестнадцатеричном формате для режима CBC. "
                "При шифровании CBC, если IV не указан, он генерируется автоматически. "
                "При расшифровании CBC, если IV не указан, он читается из первых 16 байт входного файла."
            ),
        )


def load_key_from_args(args: argparse.Namespace) -> bytes:
    """
    Загрузка ключа из аргументов командной строки.

    Ключ может быть передан напрямую через --key
    или считан из файла через --key-file.
    """
    if args.key_file is not None:
        key_hex = read_text_file(args.key_file)
        return parse_hex_key(key_hex, args.aes)

    return parse_hex_key(args.key, args.aes)


def run_encrypt(args: argparse.Namespace) -> int:
    """
    Шифрование исходного файла с открытым текстом
    с использованием выбранного варианта AES и режима работы.
    """
    input_path = Path(args.input)
    output_path = Path(args.output)

    data = read_binary_file(input_path)
    key = load_key_from_args(args)

    if args.mode == "ecb":
        ciphertext = encrypt_ecb(data, key, args.aes)
        write_binary_file(output_path, ciphertext)

        print("Шифрование успешно завершено.")
        print("Режим                 : ECB")
        print(f"AES                   : AES-{args.aes}")
        print(f"Исходный файл        : {input_path}")
        print(f"Файл вывода          : {output_path}")
        print(f"Размер входных данных : {len(data)} байт")
        print(f"Размер выходных данных: {len(ciphertext)} байт")
        return 0

    if args.mode == "cbc":
        iv = parse_hex_iv(args.iv) if args.iv else None
        generated_iv, ciphertext = encrypt_cbc(data, key, args.aes, iv=iv)

        if args.iv:
            output_data = ciphertext
        else:
            output_data = prepend_iv(generated_iv, ciphertext)

        write_binary_file(output_path, output_data)

        print("Шифрование успешно завершено.")
        print("Режим                 : CBC")
        print(f"AES                   : AES-{args.aes}")
        print(f"Исходный файл        : {input_path}")
        print(f"Файл вывода          : {output_path}")
        print(f"Размер входных данных : {len(data)} байт")
        print(f"Размер выходных данных: {len(output_data)} байт")
        print(f"IV                    : {generated_iv.hex()}")
        if not args.iv:
             print("Примечание            : выходной файл содержит IV + шифртекст.")
        return 0

    raise ValueError(f"Неподдерживаемый режим: {args.mode}")


def run_decrypt(args: argparse.Namespace) -> int:
    """
    Расшифрование исходного файла с шифртекстом
    с использованием выбранного варианта AES и режима работы.
    """
    input_path = Path(args.input)
    output_path = Path(args.output)

    data = read_binary_file(input_path)
    key = load_key_from_args(args)

    if args.mode == "ecb":
        plaintext = decrypt_ecb(data, key, args.aes)
        write_binary_file(output_path, plaintext)

        print("Расшифрование успешно завершено.")
        print("Режим                 : ECB")
        print(f"AES                   : AES-{args.aes}")
        print(f"Исходный файл        : {input_path}")
        print(f"Файл вывода          : {output_path}")
        print(f"Размер входных данных : {len(data)} байт")
        print(f"Размер выходных данных: {len(plaintext)} байт")
        return 0

    if args.mode == "cbc":
        if args.iv:
            iv = parse_hex_iv(args.iv)
            ciphertext = data
            iv_source = "командная строка"
        else:
            iv, ciphertext = extract_iv(data)
            iv_source = "заголовок входного файла"

        plaintext = decrypt_cbc(ciphertext, key, args.aes, iv)
        write_binary_file(output_path, plaintext)

        print("Расшифрование успешно завершено.")
        print("Режим                 : CBC")
        print(f"AES                   : AES-{args.aes}")
        print(f"Исходный файл        : {input_path}")
        print(f"Файл вывода          : {output_path}")
        print(f"Размер входных данных : {len(data)} байт")
        print(f"Размер выходных данных: {len(plaintext)} байт")
        print(f"IV                    : {iv.hex()}")
        print(f"Источник IV           : {iv_source}")
        return 0

    raise ValueError(f"Неподдерживаемый режим: {args.mode}")


def main() -> int:
    """
    Точка входа программы.
    Выполняет разбор аргументов командной строки и запуск выбранной операции.
    """
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            return run_encrypt(args)

        if args.command == "decrypt":
            return run_decrypt(args)

        parser.error(f"Неизвестная команда: {args.command}")
        return 2

    except FileNotFoundError as exc:
        print(f"Ошибка файла: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Ошибка доступа: {exc}", file=sys.stderr)
        return 1
    except (AESException, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
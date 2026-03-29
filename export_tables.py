from __future__ import annotations

from pathlib import Path

from aes.constants import INV_S_BOX, RCON, S_BOX
from aes.sbox_math import generate_inv_s_box, generate_rcon, generate_s_box


def format_hex_table(name: str, values: tuple[int, ...], per_line: int = 16) -> str:
    """
    Форматирование таблицы байтов в текстовом виде.
    """
    lines = [f"{name} ({len(values)} значений):"]

    for i in range(0, len(values), per_line):
        chunk = values[i:i + per_line]
        line = ", ".join(f"0x{value:02X}" for value in chunk)
        lines.append(line)

    return "\n".join(lines)


def format_check_result(name: str, generated: tuple[int, ...], reference: tuple[int, ...]) -> str:
    """
    Форматирование результатов сравнения с эталонной таблицей.
    """
    if generated == reference:
        return f"{name}: СОВПАДАЕТ"

    lines = [f"{name}: НЕ СОВПАДАЕТ"]

    max_len = min(len(generated), len(reference))
    for index in range(max_len):
        if generated[index] != reference[index]:
            lines.append(
                f"Первое отличие на позиции {index}: "
                f"Сгенерировано 0x{generated[index]:02X}, "
                f"Ожидалось 0x{reference[index]:02X}"
            )
            break
    else:
        if len(generated) != len(reference):
            lines.append(
                f"Разная длина: сгенерировано {len(generated)}, "
                f"Ожидалось {len(reference)}"
            )

    return "\n".join(lines)


def main() -> None:
    """
    Генерация S-box, Inv-S-box и Rcon,
    проверка их соответствия эталонным константам AES,
    сохранение результатов в текстовый файл.
    """
    s_box = generate_s_box()
    inv_s_box = generate_inv_s_box()
    rcon = generate_rcon(len(RCON))

    checks = [
        format_check_result("S-box", s_box, S_BOX),
        format_check_result("Inv-S-box", inv_s_box, INV_S_BOX),
        format_check_result("Rcon", rcon, RCON),
    ]

    sections = [
        "Алгоритмически сгенерированные таблицы AES",
        "=" * 60,
        "",
        "Результаты проверки соответствия эталонным константам:",
        *checks,
        "",
        "=" * 60,
        "",
        format_hex_table("S-box", s_box),
        "",
        format_hex_table("Inv-S-box", inv_s_box),
        "",
        format_hex_table("Rcon", rcon, per_line=10),
        "",
    ]

    output_text = "\n".join(sections)

    output_path = Path("generated_aes_tables.txt")
    output_path.write_text(output_text, encoding="utf-8")

    print(f"Файл успешно создан: {output_path.resolve()}")


if __name__ == "__main__":
    main()
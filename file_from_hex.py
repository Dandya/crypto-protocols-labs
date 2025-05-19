def hex_string_to_file(hex_string: str, output_file: str):
    """
    Преобразует строку hex (big-endian) в файл.

    :param hex_string: Строка в шестнадцатеричном формате (например, "48656C6C6F")
    :param output_file: Имя выходного файла (например, "output.bin")
    """
    try:
        # Удаляем возможные пробелы и префиксы (0x, \x и т. д.)
        hex_string = hex_string.strip().replace(" ", "").replace("0x", "").replace("\\x", "")

        # Проверяем, что строка имеет четную длину
        if len(hex_string) % 2 != 0:
            raise ValueError("Некорректная hex-строка: длина должна быть чётной")

        # Преобразуем hex в байты (big-endian)
        data = bytes.fromhex(hex_string)[::-1]

        # Записываем байты в файл
        with open(output_file, "wb") as f:
            f.write(data)

        print(f"Файл {output_file} успешно создан, записано {len(data)} байт.")

    except ValueError as e:
        print(f"Ошибка: {e}")
    except Exception as e:
        print(f"Неизвестная ошибка: {e}")

# Пример использования
if __name__ == "__main__":
    hex_str = "8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59"
    output_filename = "output.bin"
    hex_string_to_file(hex_str, output_filename)
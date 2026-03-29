class AESException(Exception):
    """Базовое исключение AES."""


class InvalidKeyLengthError(AESException):
    """Неверная длина ключа."""


class InvalidBlockSizeError(AESException):
    """Неверный размер блока."""


class InvalidPaddingError(AESException):
    """Некорректное дополнение PKCS#7."""


class InvalidIVError(AESException):
    """Отсутствующий или некорректный IV."""


class InvalidCiphertextLengthError(AESException):
    """
    Ошибка длины шифртекста.
    """
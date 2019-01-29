from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def signature_remove(jwt_string):
    """
    Completely removes the signature

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, _ = decode_jwt(jwt_string)
    yield encode_jwt(header, payload, '')


def signature_zero(jwt_string):
    """
    0x00

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, _ = decode_jwt(jwt_string)
    yield encode_jwt(header, payload, '\0')


def signature_reverse(jwt_string):
    """
    Reverse the signature string

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    signature = signature[::-1]
    yield encode_jwt(header, payload, signature)


def signature_random_letters(jwt_string):
    """
    Put random letters in signature

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().signature_random_letters(jwt_string)


def signature_random_digits(jwt_string):
    """
    Put random digits in signature

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().signature_random_digits(jwt_string)

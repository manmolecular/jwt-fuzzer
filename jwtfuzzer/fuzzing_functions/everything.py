from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def all_empty(jwt_string):
    """
    Completely removes all fields

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield encode_jwt('', '', '')


def multiple_dots(jwt_string):
    """
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield '..................'


def random_letters(jwt_string):
    """
    Put random letters in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().token_random_letters()


def random_digits(jwt_string):
    """
    Put random digits in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().token_random_digits()


def token_zero(jwt_string):
    """
    Put 0 in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield 0


def token_one(jwt_string):
    """
    Put 1 in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield 1


def token_minus_one(jwt_string):
    """
    Put -1 in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield -1


def token_none(jwt_string):
    """
    Put None in token place

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    yield None

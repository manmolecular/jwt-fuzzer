from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def header_typ_empty(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": ""
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = ''
    yield encode_jwt(header, payload, signature)


def header_typ_remove(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        del header['typ']
    except KeyError:
        # Some JWT implementations, such as the one used by Google, doesn't
        # send the typ header parameter
        return

    yield encode_jwt(header, payload, signature)


def header_typ_null(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": null
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = None
    yield encode_jwt(header, payload, signature)


def header_typ_invalid(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": "invalid"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_typ_binary_decode_error(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": "\xc3\xb1"
        }

    In some languages (like python) encoding and decoding strings can be hard
    and trigger UnicodeDecodeErrors. Try this in a python console:

        >>> str(u'\xc3\xb1')
        UnicodeEncodeError: 'ascii' codec can't encode characters in position 0-1: ordinal not in range(128)

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = '\xc3\xb1'
    yield encode_jwt(header, payload, signature)


def header_typ_none(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "HS256",
          "typ": "none"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['typ'] = 'none'
    yield encode_jwt(header, payload, signature)


def header_typ_random_digits(jwt_string):
    """
    Put random digits in typ field. Function returns
    generator with 1, 10, 100, 1000, 10000 random digits.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_digits(jwt_string, 'typ')


def header_typ_random_letters(jwt_string):
    """
    Put random ASCII letters in typ field. Function returns
    generator with 1, 10, 100, 1000, 10000 random letters.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_letters(jwt_string, 'typ')


def header_typ_none_variations(jwt_string):
    """
    Put different variations of none in typ field, for example,
    none, None, nOne, etc ...

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_none_variation(jwt_string, 'typ')


def header_typ_null_variations(jwt_string):
    """
    Put different variations of null in typ field, for example,
    null, Null, nUll, etc ...
    
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_null_variation(jwt_string, 'typ')


def header_typ_fuzz_list(jwt_string):
    """
    Fuzz typ field with user input fuzz wordlist

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_basic_fuzz_list(jwt_string, 'typ')

from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def header_alg_empty(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = ''
    yield encode_jwt(header, payload, signature)


def header_alg_remove(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    del header['alg']
    yield encode_jwt(header, payload, signature)


def header_alg_null(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": null,
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = None
    yield encode_jwt(header, payload, signature)


def header_alg_invalid(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "invalid",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_alg_binary_decode_error(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "\xc3\xb1",
          "typ": "JWT"
        }

    In some languages (like python) encoding and decoding strings can be hard
    and trigger UnicodeDecodeErrors. Try this in a python console:

        >>> str(u'\xc3\xb1')
        UnicodeEncodeError: 'ascii' codec can't encode characters in position 0-1: ordinal not in range(128)

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = '\xc3\xb1'
    yield encode_jwt(header, payload, signature)


def header_alg_none(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "none",
          "typ": "JWT"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'none'
    yield encode_jwt(header, payload, signature)


def header_alg_none_empty_sig(jwt_string):
    """
    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "none",
          "typ": "JWT"
        }

    We also remove the signature

    Exactly as described in https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['alg'] = 'none'
    signature = ''
    yield encode_jwt(header, payload, signature)


VALID_ALGS = ['HS256',
              'HS384',
              'HS512',
              'RS256',
              'RS384',
              'RS512',
              'ES256',
              'ES384',
              'ES512']


def header_alg_all_possible_values(jwt_string):
    """
    JWT RFC says that these are all the valid values for the alg field:

        HS256	HMAC using SHA-256 hash algorithm
        HS384	HMAC using SHA-384 hash algorithm
        HS512	HMAC using SHA-512 hash algorithm
        RS256	RSA using SHA-256 hash algorithm
        RS384	RSA using SHA-384 hash algorithm
        RS512	RSA using SHA-512 hash algorithm
        ES256	ECDSA using P-256 curve and SHA-256 hash algorithm
        ES384	ECDSA using P-384 curve and SHA-384 hash algorithm
        ES512	ECDSA using P-521 curve and SHA-512 hash algorithm

    If the header looks like:
        {
            "alg": "HS256",
            "typ": "JWT"
        }

    The result will look like:
        {
          "alg": "...",
          "typ": "JWT"
        }

    Where ... will be each of the valid values for the alg field.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    original_alg = header['alg']
    valid_algs = VALID_ALGS[:]

    # We want to yield different things, if we don't remove the original
    # alg we'll be yielding the exact same JWT
    if original_alg in valid_algs:
        valid_algs.remove(original_alg)

    for alg in valid_algs:
        header['alg'] = alg
        yield encode_jwt(header, payload, signature)


def header_alg_random_digits(jwt_string):
    """
    Put random digits in alg field. Function returns
    generator with 1, 10, 100, 1000, 10000 random digits.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_digits(jwt_string, 'alg')

def header_alg_random_letters(jwt_string):
    """
    Put random ASCII letters in alg field. Function returns
    generator with 1, 10, 100, 1000, 10000 random letters.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_letters(jwt_string, 'alg')


def header_alg_none_variations(jwt_string):
    """
    Put different variations of none in alg field, for example,
    none, None, nOne, etc ...

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_none_variation(jwt_string, 'alg')


def header_alg_null_variations(jwt_string):
    """
    Put different variations of null in alg field, for example,
    null, Null, nUll, etc ...
    
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_null_variation(jwt_string, 'alg')


def header_alg_fuzz_list(jwt_string):
    """
    Fuzz alg field with user input fuzz wordlist

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_basic_fuzz_list(jwt_string, 'alg')

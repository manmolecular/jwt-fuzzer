from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def header_kid_empty(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": ""
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = ''
    yield encode_jwt(header, payload, signature)


def header_kid_remove(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        del header['kid']
    except KeyError:
        # When the JWT is signed using hashes, there is no kid
        return

    yield encode_jwt(header, payload, signature)


def header_kid_null(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": null
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = None
    yield encode_jwt(header, payload, signature)


def header_kid_invalid(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "invalid"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = 'invalid'
    yield encode_jwt(header, payload, signature)


def header_kid_none(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "none"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    header['kid'] = 'none'
    yield encode_jwt(header, payload, signature)


def header_kid_reverse(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    try:
        header['kid'] = header['kid'][::-1]
    except KeyError:
        # When the JWT is signed using hashes, there is no kid
        return

    yield encode_jwt(header, payload, signature)


def header_kid_self_reference(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "/./b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    # When the JWT is signed using hashes, there is no kid
    if 'kid' not in header:
        return

    header['kid'] = '/./' + header['kid']
    yield encode_jwt(header, payload, signature)


def header_kid_file_url(jwt_string):
    """
    If the header looks like:
        {
          "alg": "RS256",
          "kid": "ac2b63faefcf8362f4c528e7c78433879387016b"
        }

    The result will look like:
        {
          "alg": "RS256",
          "kid": "file://b61078397833487c7e825c4f2638fcfeaf36b2ca"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    # When the JWT is signed using hashes, there is no kid
    if 'kid' not in header:
        return

    header['kid'] = 'file://' + header['kid']
    yield encode_jwt(header, payload, signature)


def header_kid_random_digits(jwt_string):
    """
    Put random digits in kid field. Function returns
    generator with 1, 10, 100, 1000, 10000 random digits.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_digits(jwt_string, 'kid')


def header_kid_random_letters(jwt_string):
    """
    Put random ASCII letters in kid field. Function returns
    generator with 1, 10, 100, 1000, 10000 random letters.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_letters(jwt_string, 'kid')


def header_kid_none_variations(jwt_string):
    """
    Put different variations of none in kid field, for example,
    none, None, nOne, etc ...

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_none_variation(jwt_string, 'kid')


def header_kid_null_variations(jwt_string):
    """
    Put different variations of null in kid field, for example,
    null, Null, nUll, etc ...
    
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_null_variation(jwt_string, 'kid')


def header_kid_fuzz_list(jwt_string):
    """
    Fuzz kid field with user input fuzz wordlist

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_basic_fuzz_list(jwt_string, 'kid')

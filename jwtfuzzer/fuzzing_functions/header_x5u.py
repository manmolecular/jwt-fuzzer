from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def header_x5u_remove(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)
    try:
        del header['x5u']
    except:
        return
    else:
        yield encode_jwt(header, payload, signature)


def header_x5u_dev_null(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "/dev/null",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = '/dev/null'
    yield encode_jwt(header, payload, signature)


def header_x5u_self_reference(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "/./key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = '/./' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_url(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "https://localhost/key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'http://localhost/' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_file_url(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "file://key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'file://' + header['x5u']
    yield encode_jwt(header, payload, signature)


def header_x5u_file_url_root(jwt_string):
    """
    If the header looks like:
        {
            "x5u": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "x5u": "file:///",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'x5u' not in header:
        return

    header['x5u'] = 'file:///'
    yield encode_jwt(header, payload, signature)


def header_x5u_random_digits(jwt_string):
    """
    Put random digits in x5u field. Function returns
    generator with 1, 10, 100, 1000, 10000 random digits.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_digits(jwt_string, 'x5u')


def header_x5u_random_letters(jwt_string):
    """
    Put random ASCII letters in x5u field. Function returns
    generator with 1, 10, 100, 1000, 10000 random letters.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_letters(jwt_string, 'x5u')


def header_x5u_none_variations(jwt_string):
    """
    Put different variations of none in x5u field, for example,
    none, None, nOne, etc ...

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_none_variation(jwt_string, 'x5u')


def header_x5u_null_variations(jwt_string):
    """
    Put different variations of null in x5u field, for example,
    null, Null, nUll, etc ...
    
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_null_variation(jwt_string, 'x5u')


def header_x5u_fuzz_list(jwt_string):
    """
    Fuzz x5u field with user input fuzz wordlist

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_basic_fuzz_list(jwt_string, 'x5u')

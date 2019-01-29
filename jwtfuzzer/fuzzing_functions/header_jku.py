from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def header_jku_remove(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
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
        del header['jku']
    except:
        return
    else:
        yield encode_jwt(header, payload, signature)


def header_jku_dev_null(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "/dev/null",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = '/dev/null'
    yield encode_jwt(header, payload, signature)


def header_jku_self_reference(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "/./key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = '/./' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_url(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "https://localhost/key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'http://localhost/' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_file_url(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "file://key-1.cer",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'file://' + header['jku']
    yield encode_jwt(header, payload, signature)


def header_jku_file_url_root(jwt_string):
    """
    If the header looks like:
        {
            "jku": "key-1.cer",
            "alg": "RS256"
        }

    The result will look like:
        {
            "jku": "file:///",
            "alg": "RS256"
        }

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    header, payload, signature = decode_jwt(jwt_string)

    if 'jku' not in header:
        return

    header['jku'] = 'file:///'
    yield encode_jwt(header, payload, signature)


def header_jku_random_digits(jwt_string):
    """
    Put random digits in jku field. Function returns
    generator with 1, 10, 100, 1000, 10000 random digits.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_digits(jwt_string, 'jku')


def header_jku_random_letters(jwt_string):
    """
    Put random ASCII letters in jku field. Function returns
    generator with 1, 10, 100, 1000, 10000 random letters.

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_random_letters(jwt_string, 'jku')


def header_jku_none_variations(jwt_string):
    """
    Put different variations of none in jku field, for example,
    none, None, nOne, etc ...

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_none_variation(jwt_string, 'jku')


def header_jku_null_variations(jwt_string):
    """
    Put different variations of null in jku field, for example,
    null, Null, nUll, etc ...
    
    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_null_variation(jwt_string, 'jku')


def header_jku_fuzz_list(jwt_string):
    """
    Fuzz jku field with user input fuzz wordlist

    :param jwt_string: The JWT as a string
    :return: The fuzzed JWT
    """
    return FuzzHelpers().header_basic_fuzz_list(jwt_string, 'jku')

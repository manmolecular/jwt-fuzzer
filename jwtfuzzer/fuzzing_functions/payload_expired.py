from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt
from custom_helpers import FuzzHelpers


def payload_remove_exp(jwt_string):
    """
    Removes the exp attribute from the payload (if it exists)

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'exp' in payload:
            del payload['exp']
            yield encode_jwt(header, payload, signature)


def payload_null_exp(jwt_string):
    """
    Sets the exp attribute to null

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        payload['exp'] = None
        yield encode_jwt(header, payload, signature)


def payload_exp_one(jwt_string):
    """
    Sets the exp attribute to 1

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'exp' in payload:
            payload['exp'] = 1
            yield encode_jwt(header, payload, signature)


def payload_exp_minus_one(jwt_string):
    """
    Sets the exp attribute to -1

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'exp' in payload:
            payload['exp'] = -1
            yield encode_jwt(header, payload, signature)


def payload_exp_zero(jwt_string):
    """
    Sets the exp attribute to 0

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'exp' in payload:
            payload['exp'] = 0
            yield encode_jwt(header, payload, signature)


def payload_exp_string(jwt_string):
    """
    Sets the exp attribute to a string

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    header, payload, signature = decode_jwt(jwt_string)

    if isinstance(payload, dict):
        if 'exp' in payload:
            payload['exp'] = str(payload['exp'])
            yield encode_jwt(header, payload, signature)


def payload_exp_random_string(jwt_string):
    """
    Sets the exp attribute to different long strings

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    return FuzzHelpers().payload_random_letters(jwt_string, 'exp')


def payload_exp_random_digits(jwt_string):
    """
    Sets the exp attribute to different long digits

    :param jwt_string: The JWT as a string
    :yield: The different JWT as string
    """
    return FuzzHelpers().payload_random_digits(jwt_string, 'exp')
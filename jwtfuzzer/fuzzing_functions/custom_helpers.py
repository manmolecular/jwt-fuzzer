from random import choice as random_choice
from string import digits, ascii_letters
from jwtfuzzer.decoder import decode_jwt
from jwtfuzzer.encoder import encode_jwt


class FuzzHelpers:
    """
    Some useful functions to work with
    similiar fuzzing methods
    """
    fuzz_list = None

    def __init__(self):
        pass

    def header_basic_fuzz_list(self, jwt_string, field):
        """
        Fuzz headers with wordlist

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        header, payload, signature = decode_jwt(jwt_string)
        if not self.fuzz_list:
            return
        try:
            with open(self.fuzz_list, 'r') as file:
                for current_payload in file:
                    header[field] = current_payload
                    yield encode_jwt(header, payload, signature)
        except:
            return

    def signature_basic_fuzz_list(self, jwt_string, field):
        """
        Fuzz signature with wordlist

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        header, payload, signature = decode_jwt(jwt_string)
        if not self.fuzz_list:
            return
        try:
            with open(self.fuzz_list, 'r') as file:
                for current_payload in file:
                    signature = current_payload
                    yield encode_jwt(header, payload, signature)
        except:
            return

    def header_null_variation(self, jwt_string, field):
        """
        Trying different None (python) combinations

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        header, payload, signature = decode_jwt(jwt_string)
        none_variations = ['null', 'Null', 'nUll', 
                        'nuLl', 'nulL', 'NULL', 
                        'nULL', 'NuLL', 'NUlL', 'NULl']
        for current_none in none_variations:
            header[field] = current_none
            yield encode_jwt(header, payload, signature)

    def header_none_variation(self, jwt_string, field):
        """
        Trying different None (python) combinations

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        header, payload, signature = decode_jwt(jwt_string)
        none_variations = ['none', 'None', 'nOne', 
                        'noNe', 'nonE', 'n0ne', 
                        'NONE', 'NoNe', 'nOnE']
        for current_none in none_variations:
            header[field] = current_none
            yield encode_jwt(header, payload, signature)

    def header_random_letters(self, jwt_string, field):
        """
        Put random letters in field, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            letters_number = int('1' + '0' * zero_count)
            header[field] = ''.join([random_choice(ascii_letters) for _ in range(letters_number)])
            yield encode_jwt(header, payload, signature)

    def header_random_digits(self, jwt_string, field):
        """
        Put random digits in field, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            digits_number = int('1' + '0' * zero_count)
            header[field] = ''.join([random_choice(digits) for _ in range(digits_number)])
            yield encode_jwt(header, payload, signature)

    def payload_random_letters(self, jwt_string, field):
        """
        Put random letters in payload field, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            letters_number = int('1' + '0' * zero_count)
            payload[field] = ''.join([random_choice(ascii_letters) for _ in range(letters_number)])
            yield encode_jwt(header, payload, signature)

    def payload_random_digits(self, jwt_string, field):
        """
        Put random digits in payload field, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            digits_number = int('1' + '0' * zero_count)
            payload[field] = ''.join([random_choice(digits) for _ in range(digits_number)])
            yield encode_jwt(header, payload, signature)

    def signature_random_letters(self, jwt_string):
        """
        Put random letters in signature, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            letters_number = int('1' + '0' * zero_count)
            signature = ''.join([random_choice(ascii_letters) for _ in range(letters_number)])
            yield encode_jwt(header, payload, signature)

    def signature_random_digits(self, jwt_string):
        """
        Put random digits in signature, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """
        
        header, payload, signature = decode_jwt(jwt_string)
        for zero_count in range(5):
            digits_number = int('1' + '0' * zero_count)
            signature = ''.join([random_choice(digits) for _ in range(digits_number)])
            yield encode_jwt(header, payload, signature)

    def token_random_letters(self):
        """
        Put random letters in token, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """

        for zero_count in range(5):
            letters_number = int('1' + '0' * zero_count)
            yield ''.join([random_choice(ascii_letters) for _ in range(letters_number)])

    def token_random_digits(self):
        """
        Put random digits in token, from 1 to 10.000

        :param jwt_string: the JWT as a string
        :return: The fuzzed JWT
        """

        for zero_count in range(5):
            digits_number = int('1' + '0' * zero_count)
            yield ''.join([random_choice(digits) for _ in range(digits_number)])

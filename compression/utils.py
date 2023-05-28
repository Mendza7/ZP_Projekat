import base64
import zlib

def compress_string(string_to_compress):
    input_data = string_to_compress.encode('utf-8')

    compressed_data = zlib.compress(input_data, level=zlib.Z_BEST_COMPRESSION)

    return compressed_data

def decompress_string(compressed_bytes):

    decompressed_data = zlib.decompress(compressed_bytes)

    # Convert the decompressed data to a string
    uncompressed_string = decompressed_data.decode('utf-8')

    # Return the uncompressed string
    return uncompressed_string


def encode_string(string_to_encode):
    # Convert the string to bytes
    input_data = string_to_encode.encode('utf-8')

    # Encode the input data using base64
    encoded_data = base64.b64encode(input_data)

    # Convert the encoded data to a string
    encoded_string = encoded_data.decode('utf-8')

    # Return the encoded string
    return encoded_string


def decode_string(string_to_decode):
    # Convert the string to bytes
    input_data = string_to_decode.encode('utf-8')

    # Decode the input data using base64
    decoded_data = base64.b64decode(input_data)

    # Convert the decoded data to a string
    decoded_string = decoded_data.decode('utf-8')

    # Return the decoded string
    return decoded_string


if (__name__=='__main__'):
    test_string = "This is a test string"
    print(test_string)
    print(compress_string(test_string))
    print(decompress_string(compress_string(test_string)))

    print(encode_string(test_string))
    print(decode_string(encode_string(test_string)))
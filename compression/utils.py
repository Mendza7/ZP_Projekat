import base64
import binascii
import zlib

def compress_string(string_to_compress):
    input_data = string_to_compress.encode('utf-8')

    compressed_data = zlib.compress(input_data, level=zlib.Z_BEST_COMPRESSION)

    return compressed_data

def decompress_string(compressed_bytes):

    decompressed_data = zlib.decompress(compressed_bytes)

    uncompressed_string = decompressed_data.decode('utf-8')

    return uncompressed_string


def encode_string(string_to_encode):
    input_data = string_to_encode.encode('utf-8')

    encoded_data = base64.b64encode(input_data)

    encoded_string = encoded_data.decode('utf-8')

    return encoded_string


def decode_string(string_to_decode):
    input_data = string_to_decode.encode('utf-8')

    decoded_data = base64.b64decode(input_data)

    decoded_string = decoded_data.decode('utf-8')

    return decoded_string

def bin2hex(bytes):
    return binascii.hexlify(bytes).decode('utf-8')

def hex2bin(hexified):
    try:
        hexified = hexified.encode('utf-8')
    except Exception:
        pass
    return  binascii.unhexlify(hexified)


if (__name__=='__main__'):
    test_string = "420fa52b69feeea86bf7cde885035827353a1a236634a4dba4c2275fb77809e033cfa2aa059637e1c47064a2dd7da458a91cf26b3c41aad0cc4e530f2a68050c156a28cbcaa5a101ea0c6e209d9eb93acdc3ac3315d4aa34c146089d66a42a66a31e068b2d292c3b1c41156c0225b5e1b9041adcea6337c9c2bb00575b837b91691a32dfa6fb5fc41745cd861c9551163ad45e0c8cf45312dd6ec374a044477f5c23953192a3945b9202f12ccd6500b30deb1501995bc3e285767eb9fcd832fd247bbe6832f0ba344edce5c1d58322ec817418c44a51719998f268c4959ec9f742e3b9e4b400a4911235e4d5f28a1e76bdc7f77e460407fbf24d210e9231626fc84e57ad037f903abb421f9bf13298f2"
    print(decompress_string(hex2bin(test_string)))


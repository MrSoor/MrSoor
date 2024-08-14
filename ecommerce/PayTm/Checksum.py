import string
import base64
import random
import hashlib


from Crypto.Cipher import AES

IV = "@@@@&&&&####$$$$"
BLOCK_SIZE = 16

def _pad_(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def _unpad_(s):
    return s[:-ord(s[len(s)-1:])]

def _encode_(to_encode, iv, key):
    to_encode = _pad_(to_encode)
    c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    to_encode = c.encrypt(to_encode.encode('utf-8'))
    to_encode = base64.b64encode(to_encode)
    return to_encode.decode("UTF-8")

def _decode_(to_decode, iv, key):
    to_decode = base64.b64decode(to_decode)
    c = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv.encode('utf-8'))
    to_decode = c.decrypt(to_decode)
    to_decode = to_decode.decode('utf-8')
    return _unpad_(to_decode)

def _id_generator_(size=4, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def __get_param_string__(param_dict):
    params_string = '|'.join([str(value) for value in param_dict.values()])
    return params_string

def generate_checksum(param_dict, merchant_key, salt=None):
    params_string = __get_param_string__(param_dict)
    salt = salt if salt else _id_generator_()
    final_string = '%s|%s' % (params_string, salt)
    
    hasher = hashlib.sha256(final_string.encode())
    hash_string = hasher.hexdigest()
    hash_string += salt
    
    return _encode_(hash_string, IV, merchant_key)

def verify_checksum(param_dict, merchant_key, checksum):
    received_checksum = _decode_(checksum, IV, merchant_key)
    params_string = __get_param_string__(param_dict)
    salt = received_checksum[-4:]
    expected_string = '%s|%s' % (params_string, salt)
    
    hasher = hashlib.sha256(expected_string.encode())
    expected_checksum = hasher.hexdigest() + salt
    
    if received_checksum == expected_checksum:
        return True
    else:
        return False

if __name__ == "__main__":
    params = {
        "MID": "mid",
        "ORDER_ID": "order_id",
        "CUST_ID": "cust_id",
        "TXN_AMOUNT": "1",
        "CHANNEL_ID": "WEB",
        "INDUSTRY_TYPE_ID": "Retail",
        "WEBSITE": "XXXXXXXXXXX"
    }
    merchant_key = "xXXXXXXXXXXXXXXX"
    checksum = generate_checksum(params, merchant_key)
    print("Generated Checksum:", checksum)
    
    is_valid = verify_checksum(params, merchant_key, checksum)
    print("Checksum Verification Result:", is_valid)

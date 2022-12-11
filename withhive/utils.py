import requests
import base64
import time
import math
import json
import random
import string
import binascii

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad

from .constants import HIVE_API_GUEST_KEY

def hive_auth_crypto(data):
    key = binascii.unhexlify("22b97083e9d02ba0ccfbe1a164f2d97e9659a7cff684a0509537656d626d2277")
    iv = binascii.unhexlify("5783fee74f4701d446309189c95ff236")
    cipher = AES.new(key, AES.MODE_CBC, iv)

    ct = cipher.encrypt(pad(data.encode("utf-8"), AES.block_size))
    body = {
        "iv": "5783fee74f4701d446309189c95ff236",
        "s": "267f6e6626d32701",
        "d": "h0epeqzq6l5k",
        "ct": base64.b64encode(ct)
    }

    return body

# utility function for making a signed request to the Hive API
def hive_signed_request(endpoint, body = {}):
    hive_key_resp = requests.post(HIVE_API_GUEST_KEY, json = {})
    if hive_key_resp.status_code != 200: raise HiveAuthException("Failed to retrieve public key and signature from Hive")

    hive_key = hive_key_resp.json()
    if 'public_key' not in hive_key or 'signature' not in hive_key: raise HiveAuthException("Failed to retrieve public key and signature from Hive")

    public_key = RSA.import_key(hive_key['public_key'])
    signature = hive_key['signature']

    body = form_hive_body(body)
    body['signature'] = signature

    cipher = PKCS1_v1_5.new(public_key)
    text = cipher.encrypt(json.dumps(body).encode('utf-8'))

    resp = requests.post(endpoint, data=base64.b64encode(text).decode('utf-8'))
    if resp.status_code != 200: raise HiveAuthException("Failed to execute signed request to Hive API")

    return resp.json()

# forces a hive request body into standard format while preserving any non-standard parameters
def form_hive_body(body = {}):
    body['appid'] = "com.com2us.smon.normal.freefull.google.kr.android.common"
    body['did'] = 0
    body['native_version'] = "Hive v.4.16.0.0"
    body['hive_country'] = "US"
    body['expire_time'] = math.floor(time.time())

    return body
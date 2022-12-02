import requests
import base64
import time
import math
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from .constants import HIVE_API_GUEST_KEY

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
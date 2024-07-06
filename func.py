
import io
import json
import hashlib
import hmac
from fdk import response

def calculate_sha256(input_string):
    input_bytes = input_string.encode()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_bytes)
    hex_digest = sha256_hash.hexdigest()
    return hex_digest

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning



def handler(ctx, data: io.BytesIO=None):
    req_vars = json.loads(data.getvalue())
    secret_key = "="
    date_stamp = req_vars['data']['x-amz-date'].split('T')[0]
    region_name = 'us-ashburn-1'
    service_name = 's3'
    method='GET'
    body_hash='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    
    input_string = (
        f"{method}\n"
        "/\n"
        "\n"
        f"host:{req_vars['data']['host']}\n"
        f"x-amz-content-sha256:{req_vars['data']['x-amz-content-sha256']}\n"
        f"x-amz-date:{req_vars['data']['x-amz-date']}\n"
        "\n"
        "host;x-amz-content-sha256;x-amz-date\n"
        f"{body_hash}"
    )    

    print(f"input_string is {input_string}", flush=True)

    hash_result = calculate_sha256(input_string)    
    print(f"hash_result is {hash_result}", flush=True)

    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{req_vars['data']['x-amz-date']}\n"
        f"{date_stamp}/{region_name}/{service_name}/aws4_request\n"
        f"{hash_result}"
    )
    print(f"string_to_sign is {string_to_sign}", flush=True)

    signing_key = getSignatureKey(secret_key, date_stamp, region_name, service_name)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    print(f"signature is {signature}", flush=True)
import hashlib
import hmac
def calculate_sha256(input_string):
    # Encode the input string to bytes
    input_bytes = input_string.encode()

    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the bytes
    sha256_hash.update(input_bytes)

    # Get the hexadecimal representation of the hash
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

secret_key = "sTmJ8xdSlMiEI6zJjZT9AWYPGXMgKeNjjeNtCbQPHZg="
method="GET"
host="hl33xwzb7qcr45fxu2oxwn3b6e.apigateway.us-ashburn-1.oci.customer-oci.com"
x_amz_content_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
x_amz_date="20240706T023808Z"
body_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
date_stamp = x_amz_date.split('T')[0]
region_name = 'us-ashburn-1'
service_name = 's3'

#Create canonocial request
input_string = f"""{method}
/

host:{host}
x-amz-content-sha256:{x_amz_content_sha256}
x-amz-date:{x_amz_date}

host;x-amz-content-sha256;x-amz-date
{body_hash}"""

hash_result = calculate_sha256(input_string)
print(hash_result)
signing_key = getSignatureKey(secret_key, date_stamp, region_name, service_name)

string_to_sign = f"""AWS4-HMAC-SHA256
{x_amz_date}
{date_stamp}/us-ashburn-1/s3/aws4_request
{hash_result}"""

signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
print(signature)


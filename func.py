import io
import json
import hashlib
import hmac
import datetime
import requests  # Importing requests to make HTTP calls


def handler(ctx, data: io.BytesIO = None):
    try:
        # Extract HTTP method
        method = getattr(ctx, "Method", None)
        if callable(method):
            method = method()
        # Check if method is allowed
        print(f"Method is {method}", flush=True)
        if method not in ["GET", "PUT"]:
            return {
                "status": "error",
                "message": f"Method {method} is not supported. Only GET and PUT are allowed."
            }, 405  # 405 Method Not Allowed
        # Extract HTTP headers (normalize to lowercase)
        http_headers = getattr(ctx, "HTTPHeaders", {})
        if callable(http_headers):
            http_headers = http_headers()
        http_headers = {key.lower(): value for key, value in http_headers.items()}

        # Extract RequestURL from ctx
        request_url = getattr(ctx, "RequestURL", None)
        if callable(request_url):
            request_url = request_url()
        if not request_url:
            raise ValueError("Missing required value: RequestURL")

        # Ensure 'host' is present in headers and extract it
        if "host" not in http_headers:
            raise ValueError("Missing required header: Host")
        host = http_headers["host"]

        # Build the modified request_url:
        host_first_part = host.split('.')[0]
        modified_request_url = f"/{host_first_part}{request_url}"
        host = "ociateam.compat.objectstorage.us-ashburn-1.oraclecloud.com"

        # Set region dynamically if needed
        region_name = "us-ashburn-1"

        # Signature validation for GET requests
        signature_data = {}
        if method == "GET":
            signature_data = validate_signature(http_headers, request_url, host, region_name)
            authorization_header = signature_data["authorization_header"]
            url = f'https://{host}{request_url}'
            headers = {
                'Authorization': authorization_header,
                'X-Amz-Date': http_headers["x-amz-date"],
                'X-Amz-Content-SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }

            # Log the URL and headers
            #print(f"Invoking URL: {url}", flush=True)
            #print(f"Invoking Headers: {json.dumps(headers, indent=4)}", flush=True)

            # Send the request and return the response content directly
            try:
                response = requests.get(url, headers=headers, stream=True)
                response_body = response.raw.read()
                return response_body
            except requests.exceptions.RequestException as e:
                return str(e), 500, {}

        # Signature validation for PUT requests
        elif method == "HEAD":
            print(f"value is {host}{request_url}", flush=True)
            signature_data = validate_head_signature(http_headers, request_url, host, region_name)
            authorization_header = signature_data["authorization_header"]
            url = f'https://{host}{request_url}'
            headers = {
                'Authorization': authorization_header,
                'X-Amz-Date': http_headers["x-amz-date"],
                'X-Amz-Content-SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }

            # Log the URL and headers
            #print(f"Invoking URL: {url}", flush=True)
            #print(f"Invoking Headers: {json.dumps(headers, indent=4)}", flush=True)

            # Send the request and return the response content directly
            response = requests.head(url, headers=headers)
            return response.text, response.status_code, {}

        # Signature validation for PUT requests        
        elif method == "PUT":
            # Call the new function to generate the signature for PUT request
            req_vars = {"data": http_headers}  # Assuming headers contain necessary fields
            secret_key = "secret_key" # generate secret key
            # for enhanced security store this in secrets manager and dynamically call it
            access_key="34af0a6977a499883e42e81b3e609b61dff93ea3" # generate access key
            date_stamp = http_headers["x-amz-date"][:8]  # Extract date from x-amz-date
            auth_header = build_put_signature(http_headers, request_url, host, region_name)
            file_bytes = io.BytesIO(data.read())  # Assuming raw binary data

            # Send the PUT request with the new authorization header
            headers = {
                'Authorization': auth_header,
                'X-Amz-Date': http_headers["x-amz-date"],
                'X-Amz-Content-SHA256': http_headers["x-amz-content-sha256"],
                'Content-MD5': http_headers["content-md5"]
            }
            url = f'https://{host}{request_url}'
            # Log the URL and headers
            #print(f"Invoking PUT URL: {url}", flush=True)
            #print(f"Invoking PUT Headers: {json.dumps({'Authorization': auth_header}, indent=4)}", flush=True)

            
            response = requests.put(url, headers=headers, data=file_bytes)
            return response.text, response.status_code, {}

        return json.dumps({
            "status": "error",
            "message": "Invalid method. Only GET, PUT, and HEAD are supported."
        }), 400, {"Content-Type": "application/json"}

    except Exception as e:
        error_response = {"status": "error", "message": str(e)}
        try:
            error_response["url"] = url
            error_response["headers"] = headers
        except NameError:
            pass
        #print(f"\n--- ERROR ---\n{str(e)}", flush=True)
        return error_response


def build_put_signature(http_headers, request_url, host, region_name):
    service = 's3'
    algorithm = 'AWS4-HMAC-SHA256'
    # Required headers
    required_headers = ["x-amz-date", "authorization", "x-amz-content-sha256", "content-md5"]
    for header in required_headers:
        if header not in http_headers:
            raise ValueError(f"Missing required header: {header}")

    # Extract necessary headers
    amz_date = http_headers["x-amz-date"]
    date_stamp = amz_date[:8]  # YYYYMMDD from amz_date

    canonical_uri = request_url  # Using modified RequestURL
    canonical_headers = f'host:{host}\n'

    # Dynamically add all x-amz-* headers to canonical headers
    signed_headers = "host"
    for header, value in sorted(http_headers.items()):
        if header.startswith("x-amz-"):
            canonical_headers += f"{header}:{value}\n"
            signed_headers += f";{header}"

    payload_hash = http_headers["x-amz-content-sha256"]
    content_md5= http_headers["content-md5"]
    input_string = (
        f"PUT\n"
        f"{canonical_uri}\n"
        "\n"
        f"content-md5:{content_md5}\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:UNSIGNED-PAYLOAD\n"
        f"x-amz-date:{amz_date}\n"
        "\n"
        "content-md5;host;x-amz-content-sha256;x-amz-date\n"
        f"UNSIGNED-PAYLOAD"
    )
    #print(f"Dst OS - input_string is {input_string}", flush=True)
    hash_result = calculate_sha256(input_string)
    #print(f"Dst OS - hash_result of input_string is {hash_result}", flush=True)

    string_to_sign = (
        "AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{date_stamp}/{region_name}/{service}/aws4_request\n"
        f"{hash_result}"
    )
    #print(f"Dst OS - string_to_sign is {string_to_sign}", flush=True)
    aws_access_key_id = "34af0a6977a499883e42e81b3e609b61dff93ea3"
    aws_secret_access_key = "secret_key"
    signing_key = get_signature_key(aws_secret_access_key, date_stamp, region_name, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    #print(f"Dst OS - signature is {signature}", flush=True)

    auth_header = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={aws_access_key_id}/{date_stamp}/{region_name}/{service}/aws4_request, "
        f"SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date, "
        f"Signature={signature}"
    )
    #print(f"Auth header is {auth_header}", flush=True)

    return auth_header


def validate_signature(http_headers, request_url, host, region_name):
    """Validates an AWS S3 signature using headers dynamically, without defaults."""
    service = 's3'
    algorithm = 'AWS4-HMAC-SHA256'
    
    # Required headers
    required_headers = ["x-amz-date", "authorization", "x-amz-content-sha256"]
    for header in required_headers:
        if header not in http_headers:
            raise ValueError(f"Missing required header: {header}")

    # Extract necessary headers
    amz_date = http_headers["x-amz-date"]
    date_stamp = amz_date[:8]  # YYYYMMDD from amz_date

    canonical_uri = request_url  # Using modified RequestURL
    canonical_headers = f'host:{host}\n'

    # Dynamically add all x-amz-* headers to canonical headers
    signed_headers = "host"
    for header, value in sorted(http_headers.items()):
        if header.startswith("x-amz-"):
            canonical_headers += f"{header}:{value}\n"
            signed_headers += f";{header}"

    payload_hash = http_headers["x-amz-content-sha256"]

    canonical_request = f'GET\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    hash_result = calculate_sha256(canonical_request)
    #print(f"canonical_request is {canonical_request}", flush=True)
    #print(f"hash_result is {hash_result}", flush=True)
    string_to_sign = f'{algorithm}\n{amz_date}\n{date_stamp}/{region_name}/{service}/aws4_request\n{hash_result}'
    #print(f"string_to_sign is {string_to_sign}", flush=True)
    # Dummy AWS credentials for demonstration
    aws_access_key_id = "34af0a6977a499883e42e81b3e609b61dff93ea3"
    aws_secret_access_key = "secret_key"

    signing_key = get_signature_key(aws_secret_access_key, date_stamp, region_name, service)
    generated_signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    #print(f"generated_signature is {generated_signature}", flush=True)
    
    # Build the authorization header
    authorization_header = (
        f'{algorithm} Credential={aws_access_key_id}/{date_stamp}/{region_name}/{service}/aws4_request, '
        f'SignedHeaders={signed_headers}, Signature={generated_signature}'
    )

    # Extract the received signature from the 'authorization' header
    received_signature = http_headers["authorization"].split("Signature=")[-1]

    return {
        "is_valid": received_signature == generated_signature,
        "authorization_header": authorization_header  # Include authorization header in the return
    }

def validate_head_signature(http_headers, request_url, host, region_name):
    """Validates an AWS S3 signature using headers dynamically, without defaults."""
    service = 's3'
    algorithm = 'AWS4-HMAC-SHA256'
    
    # Required headers
    required_headers = ["x-amz-date", "authorization", "x-amz-content-sha256"]
    for header in required_headers:
        if header not in http_headers:
            raise ValueError(f"Missing required header: {header}")

    # Extract necessary headers
    amz_date = http_headers["x-amz-date"]
    date_stamp = amz_date[:8]  # YYYYMMDD from amz_date

    canonical_uri = request_url  # Using modified RequestURL
    canonical_headers = f'host:{host}\n'

    # Dynamically add all x-amz-* headers to canonical headers
    signed_headers = "host"
    for header, value in sorted(http_headers.items()):
        if header.startswith("x-amz-"):
            canonical_headers += f"{header}:{value}\n"
            signed_headers += f";{header}"

    payload_hash = http_headers["x-amz-content-sha256"]

    canonical_request = f'HEAD\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    hash_result = calculate_sha256(canonical_request)
    #print(f"canonical_request is {canonical_request}", flush=True)
    #print(f"hash_result is {hash_result}", flush=True)
    string_to_sign = f'{algorithm}\n{amz_date}\n{date_stamp}/{region_name}/{service}/aws4_request\n{hash_result}'
    #print(f"string_to_sign is {string_to_sign}", flush=True)
    # Dummy AWS credentials for demonstration
    aws_access_key_id = "34af0a6977a499883e42e81b3e609b61dff93ea3"
    aws_secret_access_key = "secret_key"

    signing_key = get_signature_key(aws_secret_access_key, date_stamp, region_name, service)
    generated_signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    #print(f"generated_signature is {generated_signature}", flush=True)
    
    # Build the authorization header
    authorization_header = (
        f'{algorithm} Credential={aws_access_key_id}/{date_stamp}/{region_name}/{service}/aws4_request, '
        f'SignedHeaders={signed_headers}, Signature={generated_signature}'
    )

    # Extract the received signature from the 'authorization' header
    received_signature = http_headers["authorization"].split("Signature=")[-1]

    return {
        "is_valid": received_signature == generated_signature,
        "authorization_header": authorization_header  # Include authorization header in the return
    }


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def calculate_sha256(input_string):
    input_bytes = input_string.encode()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_bytes)
    return sha256_hash.hexdigest()

import boto3
import logging

logging.basicConfig(
    filename=r'C:\Security\Blogs\API-GW\API-GW-Auth\s3-boto3-get-log.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
def get_s3_file(access_key, secret_key, hostname, bucket_name, object_key, download_path):
    # Create S3 client with custom endpoint
    s3_client = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        endpoint_url=hostname
    )

    # Download file
    s3_client.download_file(bucket_name, object_key, download_path)
    print(f"File {object_key} downloaded to {download_path}")


# Usage example
download_path = r'C:\Security\Blogs\API-GW\API-GW-Auth\s3-policy-based\test\1_teststse.yaml'
bucket_name = 'g62a5khpnuwmzkoxaziprd4lt4'
object_key = 'teststse.yaml'
#host_url = 'https://ociateam.compat.objectstorage.us-ashburn-1.oraclecloud.com'  # Your custom S3 host URL
hostname = f'https://g62a5khpnuwmzkoxaziprd4lt4.apigateway.us-ashburn-1.oci.customer-oci.com'
access_key = "34af0a6977a499883e42e81b3e609b61dff93ea3"  # Your AWS Access Key
secret_key = "cy/o7/K+p79kwcEfSZS+AB+EzDmp+kIUVPonGLF4UH4="  # Your AWS Secret Key

get_s3_file(access_key, secret_key, hostname, bucket_name, object_key, download_path)

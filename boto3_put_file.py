import boto3
from botocore.exceptions import NoCredentialsError
import logging

logging.basicConfig(
    filename=r'C:\Security\Blogs\API-GW\API-GW-Auth\s3-boto3-put-log.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def upload_to_s3(file_path, bucket_name, object_name, host_url, access_key, secret_key):
    # Set up the session with the provided credentials and host URL
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name='us-ashburn-1'  # Change this as per your region
    )
    
    # Create an S3 client
    s3_client = session.client('s3', endpoint_url=host_url)

    try:
        # Upload the file
        s3_client.upload_file(file_path, bucket_name, object_name)
        print(f"File {file_path} uploaded to {bucket_name}/{object_name}.")
    except FileNotFoundError:
        print(f"The file {file_path} was not found.")
    except NoCredentialsError:
        print("Credentials not available.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Usage example
file_path = r'C:\Security\Blogs\API-GW\API-GW-Auth\s3-policy-based\test\teststse.yaml'
bucket_name = 'g62a5khpnuwmzkoxaziprd4lt4'
object_name = 'teststse.yaml'
#host_url = 'https://ociateam.compat.objectstorage.us-ashburn-1.oraclecloud.com'  # Your custom S3 host URL
host_url = f'https://g62a5khpnuwmzkoxaziprd4lt4.apigateway.us-ashburn-1.oci.customer-oci.com'
access_key = "34af0a6977a499883e42e81b3e609b61dff93ea3"  # Your AWS Access Key
secret_key = "cy/o7/K+p79kwcEfSZS+AB+EzDmp+kIUVPonGLF4UH4="  # Your AWS Secret Key



upload_to_s3(file_path, bucket_name, object_name, host_url, access_key, secret_key)

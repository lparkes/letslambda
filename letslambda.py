# -*- coding: utf-8 -*-

import base64
import boto3
import hashlib
import logging
import os
import yaml
import sewer
from botocore.config import Config
from botocore.exceptions import ClientError
from datetime import datetime
from time import sleep

LOG = logging.getLogger("letslambda")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
handler.setFormatter(formatter)
# add ch to logger
LOG.addHandler(handler)

def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    try:
        s3 = conf['s3_client']
        content = s3.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to load '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

    return content

def load_config(s3, s3_bucket, letslambda_config):
    """
    Try to load the letlambda.yml out of the user bucket
    Will return None if the configuration file does not exist
    """

    try:
        conf = s3.get_object(Bucket=s3_bucket, Key=letslambda_config)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to fetch letslambda configuration '{0}' in bucket '{1}'".format(letslambda_config, s3_bucket))
        LOG.error("Error: {0}".format(e))
        return None

    return yaml.load(conf)

def save_certificates_to_s3(conf, certificate, certificate_key, account_key):
    """
    Save/overwite newly requested certificate, key and account key
    """
    domain = conf['domain']
    if certificate is not False:
        LOG.info("Saving certificate to S3")
        save_to_s3(conf, domain+".certificate.cert", certificate)
        save_to_s3(conf, domain+".certificate.key", certificate_key)
        save_to_s3(conf, "account.key.rsa", account_key)

def save_to_s3(conf, s3_key, content, encrypt=False, kms_key='AES256'):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    LOG.debug("Saving object '{0}' to in 's3://{1}'".format(s3_key, conf['s3_bucket']))
    s3 = conf['s3_client']
    kwargs = {
        'Bucket': conf['s3_bucket'],
        'Key': s3_key,
        'Body': content,
        'ACL': 'private'
    }
    if encrypt == True:
        if  kms_key != 'AES256':
            kwargs['ServerSideEncryption'] = 'aws:kms'
            kwargs['SSEKMSKeyId'] = kms_key
        else:
            kwargs['ServerSideEncryption'] = 'AES256'

    try:
        s3.put_object(**kwargs)
    except ClientError as e:
        LOG.error("Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

def lambda_handler(event, context):
    if 'bucket' not in event:
        LOG.critical("No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        LOG.critical("Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            LOG.warning("Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            LOG.warning("Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        LOG.warning("No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        LOG.info("Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']

    if 'config' not in event:
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['config']


    LOG.info("Retrieving configuration file from bucket '{0}' in region '{1}' ".format(s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:    
        LOG.critical("Cannot load letslambda configuration. Exiting.")
        exit(1)

    conf['region'] = os.environ['AWS_DEFAULT_REGION']
    conf['s3_client'] = s3_client
    conf['s3_bucket'] = s3_bucket
    conf['letslambda_config'] = letslambda_config
    conf['kms_key'] = kms_key
    request_certificate(conf)

def is_new(conf):
    return load_from_s3(conf, conf["domain"]+".certificate.cert") == None

def request_certificate(conf):
    dns_class = sewer.Route53Dns()
    # https://github.com/komuw/sewer/blob/43c3c8efae36489939d93096579ec54e941f67c7/sewer/client.py
    # 1. to create a new certificate:
    client = sewer.Client(domain_name=conf['domain'], 
                        domain_alt_names=conf['domain_alt_names'], 
                        contact_email=conf['contact_email'],
                        dns_class=dns_class,
                        account_key=load_from_s3("account.key.rsa"))
    if is_new(conf):
        print('requesting new certificate')
        certificate = client.cert()
    else:
        print('renewing existing certificate')
        certificate = client.renew()
    
    # will need to switch apache to not use chain or extract it per this issue
    certificate_key = client.certificate_key
    #https://github.com/komuw/sewer/issues/97 to get chain
    # openssl x509 -in some_certificate_and_chain.crt -text -noout
    account_key = client.account_key
    print("your certificate is:", certificate)
    #print("your certificate's key is:", certificate_key)
    #print("your letsencrypt.org account key is:", account_key)
    save_certificates_to_s3(conf, certificate, certificate_key, account_key)
    # NB: your certificate_key and account_key should be SECRET.
    # keep them very safe.

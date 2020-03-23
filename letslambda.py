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

def get_route53_zone_id(conf, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            LOG.debug("Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        LOG.error("Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        LOG.error("Error: {0}".format(e))
        return None

    return None

def reset_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn):
    """
    Remove previous challenges from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='TXT',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='TXT',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'TXT':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                LOG.info("Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                LOG.error("Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                LOG.error("Error: {0}".format(e))
                return None

            break

    LOG.debug("No Resource Record to delete.")
    return False

def create_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = { 'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': rr_type,
            'TTL': 60,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        LOG.info("Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        LOG.error("Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        LOG.error("Error: {0}".format(e))
        return None

def wait_letsencrypt_record_insync(conf, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    LOG.info("Waiting for DNS to synchronize with new TXT value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as e:
            LOG.error("Failed to retrieve record creation status.")
            LOG.error("Error: {0}".format(e))
            return None

    LOG.debug("Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def save_certificates_to_s3(conf, domain, certificate, certificate_key, account_key):
    """
    Save/overwite newly requested certificate, key and account key
    """
    if certificate is not False:
        LOG.info("Saving certificate to S3")
        save_to_s3(conf, domain['name']+".certificate.cert", certificate)
        save_to_s3(conf, domain['name']+".certificate.key", certificate_key)
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
    try:
        load_from_s3(conf, 'account.key.rsa')
    except:
        return False

def request_certificate(conf):
    dns_class = sewer.Route53()
    # https://github.com/komuw/sewer/blob/43c3c8efae36489939d93096579ec54e941f67c7/sewer/client.py
    # 1. to create a new certificate:
    client = sewer.Client(domain_name=conf['domain_name'], 
                        domain_alt_names=conf['domain_alt_names'], 
                        contact_email=conf['contact_email'],
                        dns_class=dns_class)
    if is_new(conf):
        certificate = client.cert()
    else:
        certificate = client.renew()
    
    # will need to switch apache to not use chain or extract it per this issue
    certificate_key = client.certificate_key
    #https://github.com/komuw/sewer/issues/97 to get chain
    # openssl x509 -in some_certificate_and_chain.crt -text -noout
    #chain = client.certificate_key
    account_key = client.account_key
    domain = conf['domain']
    save_certificates_to_s3(conf, domain, certificate, certificate_key, account_key)
    print("your certificate is:", certificate)
    print("your certificate's key is:", certificate_key)
    print("your letsencrypt.org account key is:", account_key)
    # NB: your certificate_key and account_key should be SECRET.
    # keep them very safe.


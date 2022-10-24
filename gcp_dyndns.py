import argparse
import configparser
import json
import logging
import sys

from google.oauth2 import service_account
from googleapiclient import discovery
from tendo import singleton
from typing import Dict

PROG_NAME = 'gcp_dyndns'


class CustomJsonFormatter(logging.Formatter):
    ''' Custom logging class format for writing JSON formatted logs'''
    def format(self, record: logging.LogRecord) -> str:
        super(CustomJsonFormatter, self).format(record)
        output = {k: str(v) for k, v in record.__dict__.items()}
        return json.dumps(output)


def setup_logging(log_file: str) -> logging.Logger:
    ''' Set up logging, preferably to a file but will
        default to stderr if no host is set
    
    :param log_file: Filename to log to
    :type log_file: str
    :return logger: Logging instance
    :rtype: logging.Logger
    '''
    logger = logging.getLogger(PROG_NAME)
    logger.setLevel(logging.DEBUG)

    # syslog handler
    json_formatter = CustomJsonFormatter()
    if log_file == 'STDERR':
        syslog_handler = logging.StreamHandler(sys.stderr)
    else:
        syslog_handler = logging.FileHandler(log_file)

    syslog_handler.setFormatter(json_formatter)
    syslog_handler.setLevel(logging.DEBUG)

    logger.addHandler(syslog_handler)

    return logger


def get_current_address_record(dns_svc: discovery.Resource, config: Dict) -> str:
    ''' Get the current A record for a FQDN in Google DNS
        we expect to only get one rrsets for type=A
        
    :param dns_svc: '''
    req = dns_svc.resourceRecordSets().list(project=config['project_id'],
                                           managedZone=config['zone_name'],
                                           name=config['a_record'],
                                           type='A')
    resp = req.execute()
    if resp is not None:
        if len(resp['rrsets']) != 1:
            raise ValueError(f'More than one rrsets for name {config["a_record"]}')
        else:
            return resp['rrsets'][0]['rrdatas'][0]


def get_current_gce_natip(cmp_svc: discovery.Resource, config: Dict) -> str:
    req = cmp_svc.instances().get(project=config['project_id'],
                                  zone=config['gce_zone'],
                                  instance=config['gce_instance'])
    resp = req.execute()
    if resp is not None:
        try:
            return resp['networkInterfaces'][0]['accessConfigs'][0]['natIP']
        except IndexError as e:
            raise IndexError(f'Unable to identify natIP for {config["gce_instance"]}')


def update_dns_record(dns_svc: discovery.Resource, dns_ip: str, gce_ip: str, config: Dict) -> Dict:
    change_body = {
        'deletions': [{
            'name': config['a_record'],
            'type': 'A',
            'ttl': 300,
            'rrdata': [dns_ip]
        }], 'additions': [{
            'name': config['a_record'],
            'type': 'A',
            'ttl': 300,
            'rrdata': [gce_ip]
        }]
    }
    req = dns_svc.changes().create(project=config['project_id'],
                                   managedZone=config['zone_name'],
                                   body=change_body)
    resp =  req.execute()

    if resp is not None:
        logger.debug(f'Updated DNS resource record: {resp}')
    else:
        return None


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('-c', '--config_file', action='store', dest='config_file',
                    required=True)
    args = ap.parse_args()
    config_file = args.config_file

    config = {}
    cfg_parser = configparser.RawConfigParser()
    cfg_parser.read(config_file)
    config['gcf'] = cfg_parser.get(PROG_NAME, 'gcp_cred_file')
    config['project_id'] = cfg_parser.get(PROG_NAME, 'project_id')
    config['zone_name'] = cfg_parser.get(PROG_NAME, 'zone_name')
    config['a_record'] = cfg_parser.get(PROG_NAME, 'a_record')
    config['gce_instance'] = cfg_parser.get(PROG_NAME, 'gce_instance')
    config['gce_zone'] = cfg_parser.get(PROG_NAME, 'gce_zone')
    config['log_file'] = cfg_parser.get(PROG_NAME, 'log_file', fallback='STDERR')

    logger = setup_logging(config['log_file'])
    logger.info(f'Starting {PROG_NAME} using config file {config_file}')

    try:
        runner = singleton.SingleInstance()
    except:
        logger.error(f'An instance of {PROG_NAME} is already running... exiting.')
        sys.exit(-1)

    gcp_creds = None

    with open(config['gcf'], 'r') as gcf:
        gcp_creds = json.load(gcf)

    svc_cred = service_account.Credentials.from_service_account_info(gcp_creds)
    dns_svc = discovery.build('dns', 'v1', credentials=svc_cred)
    cmp_svc = discovery.build('compute', 'v1', credentials=svc_cred)

    dns_ip = get_current_address_record(dns_svc, config)
    logger.info(f'Current GCP DNS entry for {config["a_record"]} is {dns_ip}')
    gce_ip = get_current_gce_natip(cmp_svc, config)
    logger.info(f'Current natIP of {config["gce_instance"]} is {gce_ip}')

    if dns_ip != gce_ip:
        logger.info(f'Updating DNS record to match GCE NAT IP')
        update_dns_record(dns_svc, dns_ip, gce_ip, config)

    dns_svc.close()
    cmp_svc.close()

    logger.info(f'Stopping {PROG_NAME}')

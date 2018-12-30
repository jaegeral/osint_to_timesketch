from __future__ import print_function
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
import configparser
import csv
from datetime import datetime
import time
import logging
import pypssl

logger = logging.getLogger('osint_timesketch')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
fh = logging.FileHandler('error.log')
fh.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(funcName)s() - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)

logger.addHandler(ch)
logger.addHandler(fh)

config = configparser.ConfigParser()
config.read("config.cfg")

API_KEY = config.get('VIRUSTOTAL', 'API_KEY')
proxy = config.get('VIRUSTOTAL', 'PROXY_URL')

PSSL_URL = config.get('VIRUSTOTAL', 'PSSL_URL')
PSSL_VERSION = int(config.get('VIRUSTOTAL', 'PSSL_VERSION'))
PSSL_USER = config.get('VIRUSTOTAL', 'PSSL_USER')
PSSL_PASSWORD = config.get('VIRUSTOTAL', 'PSSL_PASSWORD')

DELAY = config.getint('VIRUSTOTAL','DELAY')


report = config.get('VIRUSTOTAL', 'REPORT')
attribution = config.get('VIRUSTOTAL', 'ATTRIBUTION')


# hack for proxy usrs
use_proxy = config.getboolean("VIRUSTOTAL", "USE_PROXY")
if use_proxy:
    import os

    os.environ['http_proxy'] = proxy
    os.environ['HTTP_PROXY'] = proxy
    os.environ['https_proxy'] = proxy
    os.environ['HTTPS_PROXY'] = proxy

vt = VirusTotalPublicApi(API_KEY)

def convert_date_to_datetime(argument):
    """

    :rtype: datetime
    :param argument:
    :return:
    """
    argument = argument.replace('Z', '')
    #argument = argument.replace('T', ' ')
    d = datetime.strptime(argument, '%Y-%m-%d %H:%M:%S')
    iso_date = d.isoformat()
    iso_date_new = iso_date + "+00:00"
    return iso_date_new


def convert_date_to_timestamp(argument):
    """
    helper to create the timestamp

    :param argument:
    :return:
    """
    argument = argument.replace('Z', '')
    argument = argument.replace('T', ' ')

    d = datetime.strptime(argument, '%Y-%m-%d %H:%M:%S')
    unixtime = time.mktime(d.timetuple())
    unix_print = int(unixtime)
    unix_print = unix_print*1000
    return unix_print


def convert_tsdate_to_timestamp(argument):
    """
    helper to create the timestamp
    :param argument:
    :return:
    """
    argument = argument.replace('+00:00', '')
    d = datetime.strptime(argument, '%Y-%m-%d %H:%M:%S')
    unixtime = time.mktime(d.timetuple())
    unix_print = int(unixtime)
    unix_print = unix_print*1000
    #unix_print = unix_print.replace(' ', 'T')

    return unix_print


def calculate_date(offset):
    """

    :param offset:
    :return:
    """
    import datetime
    from datetime import timedelta
    calculated_date = datetime.datetime(1970,1,1)
    endDate = calculated_date + timedelta(days=int(offset))
    iso_date = endDate.isoformat()
    return iso_date


def investigate_domain(domain_to_investigate):
    """
    investigate a domain with Virustotal

    :param domain_to_investigate:
    """
    logger.debug(domain_to_investigate+" will be virustotaled")
    response = vt.get_domain_report(domain_to_investigate)
    try:
        if response['response_code'] == 200:
            # print(message, timestamp, datetime, timestamp_desc, extra_field_1, extra_field_2)
            try:
                for element in response['results']['resolutions']:
                    timestamp_desc = "VT_Domain_to_ip"
                    datetime_new = convert_date_to_datetime(element['last_resolved'])
                    ip = element['ip_address']

                    timestamp = convert_date_to_timestamp(element['last_resolved'])
                    message = "Domain " + domain_to_investigate + " was resolving to " + ip

                    source_link = "https://www.virustotal.com/gui/domain/"+domain_to_investigate+"/details"

                    append_line_to_csv(timestamp, datetime_new, timestamp_desc,message , report, attribution, source=source_link,domain=domain_to_investigate,ip=ip)

            except:
                print("Error with domain "+domain_to_investigate)
                print(json.dumps(response, sort_keys=False, indent=4))
        else:
            print(json.dumps(response, sort_keys=False, indent=4))
    except Exception as e:
        print(json.dumps(response, sort_keys=False, indent=4))


def append_line_to_csv(timestamp, datetime, timestamp_desc, message, report, attribution, source = None, md5 = None, ip=None, domain=None):
    """

    :param timestamp:
    :param datetime:
    :param timestamp_desc:
    :param message:
    :param report:
    :param attribution:
    :param source:
    :param md5:
    """
    csvwriter.writerow([timestamp, datetime, timestamp_desc, message, report, attribution, source, md5,ip,domain])



def pssl_investigate_ip(ip_to_investigate):
    """
    investigate a ip with passive SSL service

    :param ip_to_investigate:
    """
    # CIRCL passive SSL


    logger.info("Doing pSSL on: " + ip_to_investigate)

    p = pypssl.PyPSSL(PSSL_URL, PSSL_VERSION,
                      (PSSL_USER, PSSL_PASSWORD))

    # a = p.query(domain_to_investigate)
    b = p.query(ip_to_investigate + "/28")

    for ip in b:
        for certificate in b[ip]['certificates']:
            details = []
            try:
                logger.debug("Investigating "+ip_to_investigate +" cert: "+certificate)

                #cert_details = p.query_cert(certificate)

                details = p.fetch_cert(certificate)

                timestamp_desc = "pSSL_IP"
                ip = ip_to_investigate

            except ValueError as e:
                logger.error("Value Error with receiving the cert with hash: " + certificate + " from ip: " + ip_to_investigate + " " +str(e))
                continue

            except Exception as e:
                logger.error("General Error with receiving the cert with hash: "+certificate+" from ip: "+ip_to_investigate + " " +str(e))
                continue

            try:
                # FIRST_Seen
                if 'icsi' in details:
                    first_seen = details['icsi']['first_seen']
                    first_seen_datetime = calculate_date(first_seen)
                    timestamp = convert_date_to_timestamp(first_seen_datetime)
                    message = "IP " + ip + " had an SSL certificate "+certificate+" first seen in the wild " + str(first_seen_datetime) + " " + str(
                        details)

                    message = message.replace(',', ';')

                    append_line_to_csv(timestamp, first_seen_datetime, timestamp_desc, message, report, attribution,md5=certificate,ip = ip_to_investigate)

                    # LAST Seen
                    last_seen_datetime = calculate_date(details['icsi']['last_seen'])
                    timestamp = convert_date_to_timestamp(last_seen_datetime)
                    message = "IP " + ip + " had an SSL certificate " + certificate+" last seen in the wild " + str(last_seen_datetime) + " " + str(
                        details)

                    message = message.replace(',', ';')

                    append_line_to_csv(timestamp, last_seen_datetime, timestamp_desc, message, report, attribution,md5=certificate,ip = ip_to_investigate)
                else:
                    logger.debug(ip_to_investigate+" "+certificate+" no isci info found, so maybe not seen in the wild")

                # NOT AFTER

                datetime_new = details['info']['not_after']
                timestamp = convert_tsdate_to_timestamp(str(details['info']['not_after']))
                datetime_new = str(datetime_new).replace(' ', 'T')

                message = "IP " + ip + " had an SSL certificate "+certificate+" issued not after " + str(datetime_new) + " " + str(details)

                message = message.replace(',', ';')

                append_line_to_csv(timestamp, datetime_new, timestamp_desc,message, report,attribution,md5=certificate,ip = ip_to_investigate)

                # NOT BEFORE
                datetime_new = details['info']['not_before']
                timestamp = convert_tsdate_to_timestamp(str(details['info']['not_before']))
                datetime_new = str(datetime_new).replace(' ', 'T')

                message = "IP " + ip + " had an SSL certificate "+certificate+" issued not before " + str(datetime_new) + " " + str(details)
                message = message.replace(',', ';')

                append_line_to_csv(timestamp, datetime_new, timestamp_desc,message, report,attribution,md5=certificate,ip = ip_to_investigate)

                logger.debug("finished certificate")

            except Exception as e:
                logger.error("Big Error with receiving the cert with hash: " + certificate + " from ip: " + ip_to_investigate + " " + str(e))


def vt_investigate_ip(ip_to_investigate):
    """
    Investigate a ip with Virustotal to get domain related to the ip

    :param ip_to_investigate:
    """
    response = vt.get_ip_report(ip_to_investigate)
    try:
        if response['response_code']==200:

            for element in response['results']['resolutions']:
                timestamp_desc = "VT_ip_history"
                datetime_new = convert_date_to_datetime(element['last_resolved'])
                domain = element['hostname']
                ip = ip_to_investigate

                timestamp = convert_date_to_timestamp(element['last_resolved'])
                message = "IP " + ip + " was resolving to " + domain

                source_link = "https://www.virustotal.com/gui/ip-address/"+ip_to_investigate+"/relations"

                append_line_to_csv(timestamp, datetime_new, timestamp_desc,message, report, attribution,source=source_link,ip = ip_to_investigate,domain= domain)
        else:
            print(json.dumps(response, sort_keys=False, indent=4))
    except:
        logger.error("Issue with: "+ip_to_investigate)
        logger.debug(json.dumps(response, sort_keys=False, indent=4))


def investigate_md5(md5):
    """

    :param md5:
    """
    try:
        response = vt.get_file_report(md5)
        if response['response_code']==200:
            timestamp_desc = "VT_md5info"
            datetime_new = convert_date_to_datetime(response['results']['scan_date'])


            timestamp = convert_date_to_timestamp(response['results']['scan_date'])
            message = "MD5 " + md5 + " was at least scanned by VT "

            vt_source_link_source = "https://www.virustotal.com/gui/file/"+md5+"/details"

            append_line_to_csv(timestamp, datetime_new, timestamp_desc,message, report, attribution, source=vt_source_link_source,md5=md5)
        else:
            print(json.dumps(response, sort_keys=False, indent=4))
    except:
        logger.error("Issue with "+md5)
        logger.error(json.dumps(response, sort_keys=False, indent=4))


csvfile = open('output.csv', 'w', newline='')
csvwriter = csv.writer(csvfile, delimiter=',',
                       quotechar='|', quoting=csv.QUOTE_MINIMAL)

# header
csvwriter.writerow(['timestamp', 'datetime', 'timestamp_desc','message',  'report', 'attribution','source', 'md5','ip','domain'])

filename = 'input.txt'
fin=open(filename,'r')
for line in fin:
    line = line.replace('\n', '')
    line = line.replace('\t', '')
    if line.split('.')[-1].isdigit():
        # ip
        vt_investigate_ip(line)
        pssl_investigate_ip(line)
    elif "." in line:
        investigate_domain(line)
    else:
        investigate_md5(line)

    # hacky way to not go into rate limit with VT
    a = DELAY
    print(" ")
    while a != 0:
        import sys
        sys.stdout.write(str(a) + ' ')
        sys.stdout.flush()
        a=a-1
        time.sleep(1)


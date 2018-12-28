from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import configparser
import csv
from datetime import datetime
import time
config = configparser.ConfigParser()
config.read("config.cfg")

API_KEY = config.get('VIRUSTOTAL', 'API_KEY')
proxy = config.get('VIRUSTOTAL', 'PROXY_URL')

#hack for proxy users
import os

os.environ['http_proxy'] = proxy
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

vt = VirusTotalPublicApi(API_KEY)

# SET those fields if you want to write them

report = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-indicators-of-compromise-v2.2.pdf"

attribution = "APT10"


# method to create the datetime
def convert_date_to_datetime(argument):
    argument  = argument.replace('Z', '')
    d = datetime.strptime(argument, '%Y-%m-%d %H:%M:%S')
    iso_date = d.isoformat()
    iso_date_new = iso_date + "+00:00"
    return  iso_date_new
# helper to create the timestamp
def convert_date_to_timestamp(argument):
    argument = argument.replace('Z', '')
    d = datetime.strptime(argument, '%Y-%m-%d %H:%M:%S')
    unixtime = time.mktime(d.timetuple())
    unix_print = int(unixtime)
    unix_print = unix_print*1000
    return unix_print


def investigate_domain(domain_to_investigate):

    response = vt.get_domain_report(domain_to_investigate)
    if response['response_code'] == 200:
        # print(message, timestamp, datetime, timestamp_desc, extra_field_1, extra_field_2)
        try:
            for element in response['results']['resolutions']:
                timestamp_desc = "VT_Domain_to_ip"
                datetime_new = convert_date_to_datetime(element['last_resolved'])
                ip = element['ip_address']

                timestamp = convert_date_to_timestamp(element['last_resolved'])
                message = "Domain " + domain_to_investigate + " was resolving to " + ip

                print(message, timestamp, datetime_new, timestamp_desc, 'report', 'attribution')
                csvwriter.writerow([message, timestamp, datetime_new, timestamp_desc, 'report', 'attribution'])
        except:
            print("Error with domain "+domain_to_investigate)
            print(json.dumps(response, sort_keys=False, indent=4))
    else:
        print(json.dumps(response, sort_keys=False, indent=4))


def investigate_ip(ip_to_investigate):
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

                print(message, timestamp, datetime_new, timestamp_desc, 'report', 'attribution')
                csvwriter.writerow([message, timestamp, datetime_new, timestamp_desc, 'report', 'attribution'])
        else:
            print(json.dumps(response, sort_keys=False, indent=4))
    except:
        print("Issue with: "+ip_to_investigate)
        print(json.dumps(response, sort_keys=False, indent=4))

def investigate_md5(md5):
    try:
        response = vt.get_file_report(md5)
        if response['response_code']==200:
            timestamp_desc = "VT_md5info"
            datetime_new = convert_date_to_datetime(response['results']['scan_date'])


            timestamp = convert_date_to_timestamp(response['results']['scan_date'])
            message = "MD5 " + md5 + " was at least scanned by VT "

            print(message, timestamp, datetime_new, timestamp_desc, report, attribution)
            csvwriter.writerow([message, timestamp, datetime_new, timestamp_desc, report, attribution])
        else:
            print(json.dumps(response, sort_keys=False, indent=4))
    except:
        print("Issue with "+md5)
        print(json.dumps(response, sort_keys=False, indent=4))


csvfile = open('output.csv', 'w', newline='')
csvwriter = csv.writer(csvfile, delimiter=',',
                       quotechar='|', quoting=csv.QUOTE_MINIMAL)

# header
csvwriter.writerow(['message', 'timestamp', 'datetime', 'timestamp_desc', 'report', 'attribution'])

filename = 'input.txt'
fin=open(filename,'r')
for line in fin:
    line = line.replace('\n', '')
    line = line.replace('\t', '')
    if line.split('.')[-1].isdigit():
        # ip
        investigate_ip(line)
    elif "." in line:
        investigate_domain(line)
    else:
        investigate_md5(line)

    # hacky way to not go into rate limit with VT
    a = 2
    while a != 0:
        import sys
        sys.stdout.write(str(a) + ' ')
        sys.stdout.flush()
        a=a-1
        time.sleep(1)


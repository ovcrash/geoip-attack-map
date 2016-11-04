#!/usr/bin/python3

"""
AUTHOR: Matthew May - mcmay.web@gmail.com
"""

#
#   Parse CEF Log message to show on GeoIP Attack Map.
#


# Imports
import json
#import logging
import maxminddb
#import re
import redis
import re
import sys
import json
import argparse
import ipaddress

from const import META, PORTMAP, SERVICE_RGB

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from os import getuid
from sys import exit
from textwrap import dedent
from time import gmtime, localtime, sleep, strftime

# start the Redis server if it isn't started already.
# $ redis-server
# default port is 6379
# make sure system can use a lot of memory and overcommit memory

redis_ip = '127.0.0.1'
redis_instance = None

# required input paths
#syslog_path = '/var/log/syslog'
syslog_path = '/var/log/arcsight/arcsight.log'
db_path = '/db-data/GeoLite2-City.mmdb'

# file to log data
log_file_out = '/var/log/map_data_server.out'

# ip for headquarters
hq_ip = '8.8.8.8'

#Regex to filter private ip/ broadcast
IPFilter = re.compile('^(?:10|127|172|224|255|169|100|198\.(?:1[6-9]|2[0-9]|3[01]|0|255|254|100|51)|192\.168)\..*')

# stats
#server_start_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
event_count = 0
continents_tracked = {}
countries_tracked = {}
country_to_code = {}
ip_to_code = {}
ips_tracked = {}
unknowns = {}

cef_keys = set([
'_cefVer',
'act',
'ahost',
'agt',
'av',
'atz'
'aid',
'at',
'app',
'cnt',
'customerID',
'customerURI',
'dvc',
'dvchost',
'dst',
'dhost',
'destinationServiceName',
'destinationGeoCountryCode',
'destinationGeoLocationInfo',
'dlong',
'dlat',
'destinationGeoPostalCode',
'destinationGeoRegionCode',
'dmac',
'dntdom',
'dpt',
'dproc',
'duid',
'dpriv',
'duser',
'end',
'eventAnnotationStageUpdateTime',
'eventAnnotationModificationTime',
'eventAnnotationAuditTrail',
'eventAnnotationVersion',
'eventAnnotationEventId',
'eventAnnotationFlags',
'eventAnnotationEndTime',
'eventAnnotationManagerReceiptTime',
'fname',
'fsize',
'in',
'msg',
'out',
'proto',
'rt',
'request',
'src',
'shost',
'smac',
'sntdom',
'spt',
'spriv',
'suid',
'suser',
'start',
'cat',
'cs1Label',
'cs2Label',
'cs3Label',
'cs4Label',
'cs5Label',
'cs6Label',
'cn1Label',
'cn2Label',
'cn3Label',
'deviceCustomDate1Label',
'deviceCustomDate2Label',
'cs1',
'cs2',
'cs3',
'cs4',
'cs5',
'cs6',
'cn1',
'cn2',
'cn3',
'deviceNtDomain',
'deviceDnsDomain',
'deviceTranslatedAddress',
'deviceMacAddress',
'deviceCustomeDate1',
'deviceCustomDate2',
'destinationDnsDomain',
'destinationTranslatedAddress',
'destinationTranslatedPort',
'deviceDirection',
'deviceExternalId',
'deviceFacility',
'deviceInboundInterface',
'deviceOutboundInterface',
'deviceProcessName',
'deviceZoneID',
'deviceZoneURI',
'externalId',
'fileCreateTime',
'fileHash',
'fileId',
'fileModificationTime',
'filePath',
'fileType',
'oldfileCreateTime',
'oldfileHash',
'oldfileId',
'oldfileModificationTime',
'oldFilename',
'oldFilePath',
'oldfilePermission',
'oldfsize',
'oldfileType',
'mrt',
'requestClientApplication',
'requestCookies',
'requestMethod',
'sourceDnsDomain',
'sourceServiceName',
'sourceTranslatedAddress',
'sourceTranslatedPort',
'sourceGeoCountryCode',
'sourceGeoLocationInfo',
'slong',
'slat',
'sourceGeoRegionCode',
'sourceZoneURI',
'sourceZoneID',
'destinationZoneURI',
'destinationZoneID'
])

# @IDEA
#---------------------------------------------------------
# Use a class to nicely wrap everything
# You could attempt to do an acces here
# now with worrying about key errors
# Or just keep the filled data structure
#class Instance(dict):
#
#    defaults = {
#                'city': {'names':{'en':None}},
#                'continent': {'names':{'en':None}},
#                'continent': {'code':None},
#                'country': {'names':{'en':None}},
#                'country': {'iso_code':None},
#                'location': {'latitude':None},
#                'location': {'longitude':None},
#                'location': {'metro_code':None},
#                'postal': {'code':None}
#                }
#
#    def __init__(self, seed):
#        self(seed)
#        backfill()
#
#    def backfill(self):
#        for default in self.defaults:
#            if default not in self:
#                self[default] = defaults[default]
#---------------------------------------------------------

# create clean dictionary using unclean db dictionary contents
def clean_db(unclean):
    selected = {}
    for tag in META:
        head = None
        if tag['tag'] in unclean:
            head = unclean[tag['tag']]
            for node in tag['path']:
                if node in head:
                    head = head[node]
                else:
                    head = None
                    break
            selected[tag['lookup']] = head

    return selected


def connect_redis(redis_ip):
    r = redis.StrictRedis(host=redis_ip, port=6379, db=0)
    return r


def get_msg_type():
    # @TODO
    # add support for more message types later
    return "Traffic"

# check to see if packet is using an interesting TCP/UDP protocol based on source or destination port
def get_tcp_udp_proto(src_port, dst_port):
    src_port = int(src_port)
    dst_port = int(dst_port)

    if src_port in PORTMAP:
        return PORTMAP[src_port]
    if dst_port in PORTMAP:
        return PORTMAP[dst_port]

    return "OTHER"

def get_service_color(src_proto):
    src_proto = src_proto.get('protocol')
    if src_proto in SERVICE_RGB:
        return SERVICE_RGB[src_proto]

def find_hq_lat_long(hq_ip):
    hq_ip_db_unclean = parse_maxminddb(db_path, hq_ip)
    if hq_ip_db_unclean:
        hq_ip_db_clean = clean_db(hq_ip_db_unclean)
        dst_lat = hq_ip_db_clean['latitude']
        dst_long = hq_ip_db_clean['longitude']
        hq_dict = {
                'dst_lat': dst_lat,
                'dst_long': dst_long
                }
        return hq_dict
    else:
        print('Please provide a valid IP address for headquarters')
        exit()


def parse_maxminddb(db_path, ip):
    try:
        reader = maxminddb.open_database(db_path)
        response = reader.get(ip)
        reader.close()
        return response
    except FileNotFoundError:
        print('DB not found')
        print('SHUTTING DOWN')
        exit()
    except ValueError:
        return False


# @TODO
# refactor/improve parsing
# this function depends heavily on which appliances are generating logs
# for now it is only here for testing
def parse_syslog(line):
    line = line.split()
    data = line[-1]
    data = data.split(',')
    if len(data) != 4:
        print('NOT A VALID LOG')
        return False
    else:
        src_ip = data[0]
        dst_ip = data[1]
        src_port = data[2]
        dst_port = data[3]
        data_dict = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port
                    }
        return data_dict

def parse_cef(line):
    print_keys = set()
    #infile = None

    #parser = argparse.ArgumentParser(description="Process Mach-O files, perform clustering on them, and spit out Yara signatures.")
    #parser.add_argument('-a', '--add',
    #                    help='CSV list of fields to add to the default CEF ones')
    #parser.add_argument('-p', '--print_keys',
    #                    help='CSV list of fields to print, defaults to all (JSON-like output)')
    #parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    #args = parser.parse_args()

    #if args.add:
    #    add = args.add.replace(' ', '').split(',')
    #    for a in add:
    #        cef_keys.add(a)
    #keys = ['src','dst','dpt']
    #if args.print_keys:
        #pk = args.print_keys.replace(' ', '').split(',')
    #pk = print_keys.replace(' ', '').split(',')
    #for p in pk:
    #for p in keys:
    #  print_keys.add(p)

    #if not args.infile.isatty():
    #    interactive device
    #    infile = args.infile
    #else:
        #open the file here
    #    infile = open(args.infile, 'r')

    tokenlist = "|".join(cef_keys)
    regex = re.compile('('+tokenlist+')=(.*?)\s(?:'+tokenlist+'|$)')

    #for line in infile:
    parsed = {}
    tokens = re.split(r'(?<!\\)\|', line)
    Extension = ''
    if len(tokens) == 8:
        Extension = tokens[7]
    if len(tokens) > 8:
        print(len(tokens))
        sys.stderr.write("CEF Parsing error\n")
        sys.exit(1)
    parsed['CEFVersion'] = tokens[0].split('CEF:')[1]
    parsed['DeviceVendor'] = tokens[1]
    parsed['DeviceProduct'] = tokens[2]
    parsed['DeviceVersion'] = tokens[3]
    parsed['SignatureID'] = tokens[4]
    parsed['Name'] = tokens[5]
    parsed['Severity'] = tokens[6]

    continue_parsing = False
    if len(Extension) > 0:
        continue_parsing = True
    while continue_parsing:
        m = re.search(regex, Extension)
        try:
            k,v = m.groups()
            parsed[k] = v
            Extension = Extension.replace(k+'='+v, '').lstrip()
        except AttributeError:
            continue_parsing = False

    o = {}
    if len(print_keys) > 0:
        for p in print_keys:
           o[p] = parsed[p]
    else:
        o = parsed
    #print( json.dumps(o) )
    return o

    #close input file if one was opened
    #if args.infile.isatty():
    #    infile.close()


def shutdown_and_report_stats():
    print('\nSHUTTING DOWN')
    # report stats tracked
    print('\nREPORTING STATS...')
    print('\nEvent Count: {}'.format(event_count)) # report event count
    print('\nContinent Stats...') # report continents stats 
    for key in continents_tracked:
        print('{}: {}'.format(key, continents_tracked[key]))
    print('\nCountry Stats...') # report country stats
    for country in countries_tracked:
        print('{}: {}'.format(country, countries_tracked[country]))
    print('\nCountries to iso_codes...')
    for key in country_to_code:
        print('{}: {}'.format(key, country_to_code[key]))
    print('\nIP Stats...') # report IP stats
    for ip in ips_tracked:
        print('{}: {}'.format(ip, ips_tracked[ip]))
    print('\nIPs to iso_codes...')
    for key in ip_to_code:
        print('{}: {}'.format(key, ip_to_code[key]))
    print('\nUnknowns...')
    for key in unknowns:
        print('{}: {}'.format(key, unknowns[key]))
    # log stats tracked
    exit()


def menu():
    # instantiate parser
    parser = ArgumentParser(
            prog='DataServer.py',
            usage='%(progs)s [OPTIONS]',
            formatter_class=RawDescriptionHelpFormatter,
            description=dedent('''\
                    --------------------------------------------------------------
                    Data server for attack map application.
                    --------------------------------------------------------------'''))

    # @TODO --> Add support for command line args?
    # define command line arguments
    # parser.add_argument('-db', '--database', dest='db_path', required=True, type=str, help='path to maxmind database')
    # parser.add_argument('-m', '--readme', dest='readme', help='print readme')
    # parser.add_argument('-o', '--output', dest='output', help='file to write logs to')
    # parser.add_argument('-r', '--random', action='store_true', dest='randomize', help='generate random IPs/protocols for demo')
    # parser.add_argument('-rs', '--redis-server-ip', dest='redis_ip', type=str, help='redis server ip address')
    # parser.add_argument('-sp', '--syslog-path', dest='syslog_path', type=str, help='path to syslog file')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help='run server in verbose mode')

    # parse arguments/options
    args = parser.parse_args()
    return args


def merge_dicts(*args):
    super_dict = {}
    for arg in args:
        super_dict.update(arg)
    return super_dict


def track_flags(super_dict, tracking_dict, key1, key2):
    if key1 in super_dict:
        if key2 in super_dict:
            if key1 in tracking_dict:
                return None
            else:
                tracking_dict[super_dict[key1]] = super_dict[key2]
        else:
            return None
    else:
        return None


def track_stats(super_dict, tracking_dict, key):
    if key in super_dict:
        node = super_dict[key]
        if node in tracking_dict:
            tracking_dict[node] += 1
        else:
            tracking_dict[node] = 1
    else:
        if key in unknowns:
            unknowns[key] += 1
        else:
            unknowns[key] = 1

def main():
    if getuid() != 0:
        print('Please run this script as root')
        print('SHUTTING DOWN')
        exit()

    global db_path, log_file_out, redis_ip, redis_instance, syslog_path, hq_ip
    global continents_tracked, countries_tracked, ips_tracked, postal_codes_tracked, event_count, unknown, ip_to_code, country_to_code

    args = menu()

    # connect to Redis
    redis_instance = connect_redis(redis_ip)

    # find HQ lat/long
    #hq_dict = find_hq_lat_long(hq_ip)

    # follow/parse/format/publish syslog data
    with open(syslog_path, "r") as syslog_file:
        while True:
            where = syslog_file.tell()
            line = syslog_file.readline()
            if not line:
                sleep(.2)
                syslog_file.seek(where)
            else:
                #syslog_data_dict = parse_syslog(line)
                syslog_data_dict = parse_cef(line)
                if syslog_data_dict:
                    #Check if all key exist in dictionary since not always present.
                    if not all (k in syslog_data_dict for k in ("dst","spt","dpt","src")):
                        continue
                    #else:
                    #    continue
                    #Check if dst is private or mulicast
                    #checkIP = ipaddress.ip(syslog_data_dict['dst'])
                    #if checkIP.ip_private:
                    #    continue
                    if ipaddress.ip_address(syslog_data_dict['dst']).is_multicast:
                        continue
                    if IPFilter.match(syslog_data_dict['dst']):
                        continue
                    #else:
                    #    continue
                    #print('src', syslog_data_dict['src'], 'dst', syslog_data_dict['dst'])
                    ip_db_unclean = parse_maxminddb(db_path, syslog_data_dict['src'])
                    hq_dict = find_hq_lat_long(syslog_data_dict['dst'])
                    if ip_db_unclean:
                        event_count += 1
                        ip_db_clean = clean_db(ip_db_unclean)
                        if not all (k in ip_db_clean for k in ("longitude","latitude")):
                            print('---------------Skipping')
                        msg_type = {'msg_type': get_msg_type()}
                        proto = {'protocol': get_tcp_udp_proto(
                                                            #SourcePort
                                                            #syslog_data_dict['src_port'],
                                                            syslog_data_dict['spt'],
                                                            #DestinationPort
                                                            #syslog_data_dict['dst_port']
                                                            syslog_data_dict['dpt']
                                                            )}
                        #Add color for webPage show.
                        proto_color = {'color': get_service_color(proto)}
                        super_dict = merge_dicts(
                                                hq_dict,
                                                ip_db_clean,
                                                msg_type,
                                                proto,
                                                proto_color,
                                                syslog_data_dict
                                                )
                        # Track Stats
                        track_stats(super_dict, continents_tracked, 'continent')
                        track_stats(super_dict, countries_tracked, 'country')
                        track_stats(super_dict, ips_tracked, 'src')
                        event_time = strftime("%Y-%m-%d %H:%M:%S", localtime()) # local time
                        #event_time = strftime("%Y-%m-%d %H:%M:%S", gmtime()) # UTC time
                        track_flags(super_dict, country_to_code, 'country', 'iso_code')
                        track_flags(super_dict, ip_to_code, 'src', 'iso_code')

                        # Append stats to super_dict
                        super_dict['event_count'] = event_count
                        super_dict['continents_tracked'] = continents_tracked
                        super_dict['countries_tracked'] = countries_tracked
                        super_dict['ips_tracked'] = ips_tracked
                        super_dict['unknowns'] = unknowns
                        super_dict['event_time'] = event_time
                        super_dict['country_to_code'] = country_to_code
                        super_dict['ip_to_code'] = ip_to_code
                        
                        json_data = json.dumps(super_dict)
                        redis_instance.publish('attack-map-production', json_data)


                        if args.verbose:
                            print(ip_db_unclean)
                            print('------------------------')
                            print(json_data)
                            print('Event Count: {}'.format(event_count))
                            print('------------------------')

                        print('Event Count: {}'.format(event_count))
                        print('------------------------')

                    else:
                        continue


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        shutdown_and_report_stats()

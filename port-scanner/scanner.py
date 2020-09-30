import sys
import os
import yaml
import csv
import time
import nmap
import slack
from slack.errors import SlackApiError

############################## CLASS AND VARIABLES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\x1B[31;40m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

SLACK_API_TOKEN = None
SLACK_CHANNEL = None
PORTS = None

############################## CLASS AND VARIABLES <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

############################## FUNCTIONS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
def usage():
    """
    Description:
        This will print usage of the script.
    Params:
        N/A
    Returns:
        N/A
    """
    print('#' * 45 , end="")
    print(Bcolors.HEADER + ' PORT SCANNER ' + Bcolors.ENDC,end="")
    print('#' * 45)
    print(Bcolors.BOLD + """
        This script will scan open ports on server and generate report
        params position:
            1st -> Path to configuration.yaml file
            2nd -> key name of server mapping
            3rd -> Scan using private or public IPs 
                   NOTE: provide type, not the IPs i.e private_ip | public_ip

        key: value mapping in config file should be like:

        slack_api_token: <SLACK API TOKEN>
        slack_channel: '<SLACK CHANNEL CODE>'
        ports: <Array of ports>
        server_with_ip:
          - name: <name of server>
            public_ip: <public ip>
            private_ip: <private ip>

        Usage: python3 </path/to/script_name>.py </path/to/config>.yaml <key_name_of_server_mapping> <private_ip | public_ip>
    """ + Bcolors.ENDC )
    print('#' * 100)

def clean_up(csv_path: str):
    if os.path.isfile(csv_path):
        try:
            os.remove(csv_path)
            print(Bcolors.OKGREEN + f"Removed '{csv_path}' file." + Bcolors.ENDC)
        except Exception as e:
            print(Bcolors.FAIL + f"Unable to remove '{csv_path}' file.\n Error: {e}" + Bcolors.ENDC)

def send_slack_notif(csv_path: str):
    """
    Description:
        This will send csv from given path to slack channel with.
    Params:
        csv_path: str
    Returns:
        N/A
    """
    # client = slack.WebhookClient(url=SLACK_API_TOKEN)
    client = slack.WebClient(token=SLACK_API_TOKEN)

    try:
        
        # client.chat_postMessage() (text="Hello! Testing from python")
        response = client.files_upload(
            channels=SLACK_CHANNEL,
            file=csv_path,
            title=f"Port scan report -> {csv_path}",
            filename=csv_path,
            filetype='csv',
        )

        if response['ok'] is True:
            print(Bcolors.OKGREEN + f"Slack notification with csv report has been sent to '{SLACK_CHANNEL}' slack channel" + Bcolors.ENDC)

    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response['ok'] is False
        assert e.response['error']  # str like 'invalid_auth', 'channel_not_found'
        print(Bcolors.FAIL + f"Got an error: {e.response['error']}\n" + Bcolors.ENDC)
        print(Bcolors.WARNING + "Exiting now without sending report to slack channel. You can still access the file under root directory of this script" + Bcolors.ENDC)
        sys.exit(1)
    except Exception as excep:
        print(Bcolors.FAIL + f"Got an error: {excep}\n" + Bcolors.ENDC)
        print(Bcolors.WARNING + "Exiting now without sending report to slack channel. You can still access the file under root directory of this script" + Bcolors.ENDC)
        sys.exit(1)

def scan_server(servers: list, ip_type: str):
    """
    Description:
        This will take list of servers and start scanning all of them parallely. Once scan is completed, 
        it will spit out csv in the current directory.
    Params:
        servers: List of dictionaries i.e servers
    Returns:
        N/A
    """
    if len(servers) < 1:
        print( Bcolors.WARNING + "No single server record found in passed config\nExiting now." + Bcolors.ENDC)
        sys.exit(0)
    
    print( Bcolors.OKBLUE + f"Starting port scanning for {len(servers)} servers/IPs" + Bcolors.ENDC)
    nmap_style_servers_str = " ".join("{}".format(server[ip_type]) for server in servers)
    nmap_style_ports_str = ",".join("{}".format(port) for port in PORTS)
    
    scanner = nmap.PortScanner()
    # start scan
    scanner.scan(nmap_style_servers_str, nmap_style_ports_str, arguments='-Pn T4')
    # get csv 
    raw_report = scanner.csv()
    # replace ';' with ',' in csv
    raw_report = raw_report.replace(";", ",")
    # write to file
    timestr = time.strftime("%Y-%m-%d")
    filename = f"port-scan-report-{timestr}.csv"
    with open(filename, 'w', newline='') as file:
        file.write(raw_report)
    
    # send report to slack
    send_slack_notif(filename)
    clean_up(filename)
    print(Bcolors.OKGREEN + f"Port scan completed." + Bcolors.ENDC)

############################## FUNCTIONS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

############################## EXECUTION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# read config file if provided
if len(sys.argv) != 4:
    print( Bcolors.FAIL + f"ERROR! Require 4 arguments but got {len(sys.argv) - 1} \n" + Bcolors.ENDC)
    usage()
    sys.exit(1)

config_file = sys.argv[1]
config_key = sys.argv[2]
ip_type = sys.argv[3]

# check if file exist
if not os.path.isfile(config_file):
    print( Bcolors.FAIL + f"ERROR! config file '{config_file}' doesn't exist.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)

# read yaml file
print(Bcolors.OKBLUE + f"Reading {config_file}" + Bcolors.ENDC)
config_data = {}
with open(config_file, 'r') as f:
    try:
        config_data = yaml.safe_load(f)
    except yaml.YAMLError as err:
        print(Bcolors.FAIL + err + Bcolors.ENDC)

# check if config_key is valid
if not config_key in config_data:
    print( Bcolors.FAIL + f"ERROR! Missing key '{config_key}' in config file.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)

# check if ip_type is valid
if not ip_type in config_data[config_key][0].keys():
    print( Bcolors.FAIL + f"ERROR! Server mapping object doesnt contain '{ip_type}' key.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)

# check if slack api is provided
if not "slack_api_token" in config_data.keys():
    print( Bcolors.FAIL + f"ERROR! Config doesnt contain 'slack_api_token' key.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)
else:
    SLACK_API_TOKEN = config_data['slack_api_token']

# check if slack channel is provided
if not "slack_channel" in config_data.keys():
    print( Bcolors.FAIL + f"ERROR! Config doesnt contain 'slack_channel' key.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)
else:
    SLACK_CHANNEL = config_data['slack_channel']

# check if slack channel is provided
if not "ports" in config_data.keys():
    print( Bcolors.FAIL + f"ERROR! Config doesnt contain 'ports' key.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)
else:
    PORTS = config_data['ports']

# scan server
start_time = time.time()
scan_server(config_data[config_key], ip_type)
print( Bcolors.OKBLUE + 'It took {0:0.1f} seconds'.format(time.time() - start_time) + Bcolors.ENDC)
############################## EXECUTION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
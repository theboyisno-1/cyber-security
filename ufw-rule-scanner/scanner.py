import os
import sys
import yaml
import time
import paramiko
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
    print(Bcolors.HEADER + ' UFW RULES CHECKER ' + Bcolors.ENDC,end="")
    print('#' * 45)
    print(Bcolors.BOLD + """
        This script will check ufw rules on server and generate report
        params position:
            1st -> Path to configuration.yaml file
            2nd -> key name of server mapping

        key: value mapping in config file should be like:

        slack_api_token: <SLACK API TOKEN>
        slack_channel: '<SLACK CHANNEL CODE>'
        ssh_user: <SSH username>
        ssh_key_path: '<ssh private key full path>'
        ufw_servers
          - type: <server category eg. mongodb|postgres|etc>
            expect_rule_for_ports: [<List of allowed ports>]
            servers:
              - name: <Server name>
                ip: <Public IP>

        Usage: python3 </path/to/script_name>.py </path/to/config>.yaml <key_name_of_server_mapping>
    """ + Bcolors.ENDC )
    print('#' * 100)

def clean_up(file_path: str):
    if os.path.isfile(file_path):
        try:
            os.remove(file_path)
            print(Bcolors.OKGREEN + f"Removed '{file_path}' file." + Bcolors.ENDC)
        except Exception as e:
            print(Bcolors.FAIL + f"Unable to remove '{file_path}' file.\n Error: {e}" + Bcolors.ENDC)

def send_slack_notif(file_path: str):
    """
    Description:
        This will send file from given path to slack channel with.
    Params:
        file_path: str
    Returns:
        N/A
    """
    # client = slack.WebhookClient(url=SLACK_API_TOKEN)
    client = slack.WebClient(token=SLACK_API_TOKEN)

    try:
        
        # client.chat_postMessage() (text="Hello! Testing from python")
        response = client.files_upload(
            channels=SLACK_CHANNEL,
            file=file_path,
            title=f"UFW scan report -> {file_path}",
            filename=file_path,
            filetype='yaml',
        )

        if response['ok'] is True:
            print(Bcolors.OKGREEN + f"Slack notification with ufw report has been sent to '{SLACK_CHANNEL}' slack channel" + Bcolors.ENDC)

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

def check_rules(server_map: list, user: str, ssh_key_filepath: str):
    result = {}
    result['about'] = {} 
    result['about']['description'] = "This report is generated by python script which checks for ufw rule for ports which are not present in 'expect_rule_for_ports' on all the servers provided in config file."
  
    result['about']['warnings'] = ["If there is no data/keys other than this 'about' then assume that all provided servers are good." ,"Its not neccessary that ufw rules listed by this report are vulnerable, they are just rules which are not expected by the script as per given 'expect_rule_for_ports' in config file"]
    for server_categories_dict in server_map:
        server_type = server_categories_dict['type']
        expected_port_rules = server_categories_dict['expect_rule_for_ports']
        result[server_type] = {}
        result[server_type]['expect_rule_for_ports'] = expected_port_rules
        for server_dict in server_categories_dict['servers']:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    server_dict['ip'],
                    username=user,
                    key_filename=ssh_key_filepath,
                    look_for_keys=True,
                    timeout=10
                )
            except Exception as e:
                print(server_dict['name'], e)
                if client:
                    client.close()
                continue
            stdin, stdout, stderr = client.exec_command('sudo ufw status')
            stdout.channel.recv_exit_status()
            response = stdout.readlines()
            
            # close connection
            if client:
                client.close()

            # if empty then continue
            if len(response) < 1:
                continue

            rules = []
            not_expected_rules = []

            # iterate over lines in response. first 4 lines and last lines are not reauired
            for rule in response[4:-1]:
                rules.append(rule)
                words = rule.split(" ")
                if not any(str(port) in words[0] for port in expected_port_rules):
                    not_expected_rules.append(str(rule).replace("\n", ""))

            # if non expected ports rule is not there then continue
            if len(not_expected_rules) < 1:
                continue

            # create dict of result
            result[server_type][server_dict['name']] = {}
            result[server_type][server_dict['name']]['ufw_status'] = 'active' if any("Status: active" in r for r in rules[0]) else 'inactive'
            result[server_type][server_dict['name']]['not_expected_rules'] = not_expected_rules
            
    # write to file
    timestr = time.strftime("%Y-%m-%d")
    filename = f"ufw-rules-report-{timestr}.yaml"
    if result != {}:
        with open(filename, 'w') as file:
            yaml.dump(result, file, sort_keys=False)

    # send report to slack
    send_slack_notif(filename)
    clean_up(filename)
    print(Bcolors.OKGREEN + f"UFW rule scan completed." + Bcolors.ENDC)

############################## FUNCTIONS <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

############################## EXECUTION >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# read config file if provided
if len(sys.argv) != 3:
    print( Bcolors.FAIL + f"ERROR! Require 3 arguments but got {len(sys.argv) - 1} \n" + Bcolors.ENDC)
    usage()
    sys.exit(1)

config_file = sys.argv[1]
config_key = sys.argv[2]

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

# check if config_key is valid
if not 'ssh_user' in config_data:
    print( Bcolors.FAIL + f"ERROR! Missing key 'ssh_user' in config file.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)
else:
    ssh_user = config_data['ssh_user']

# check if config_key is valid
if not 'ssh_key_path' in config_data:
    print( Bcolors.FAIL + f"ERROR! Missing key 'ssh_key_path' in config file.\n" + Bcolors.ENDC)
    usage()
    sys.exit(1)
else:
    ssh_key_path = config_data['ssh_key_path']

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

# start scanning
start_time = time.time()
check_rules(config_data[config_key], ssh_user, ssh_key_path)
print( Bcolors.OKBLUE + 'It took {0:0.1f} seconds'.format(time.time() - start_time) + Bcolors.ENDC)
############################## EXECUTION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

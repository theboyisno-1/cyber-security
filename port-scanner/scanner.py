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

PORTS = [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 123, 125, 135, 137, 138, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 530, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 754, 760, 765, 777, 783, 787, 800, 801, 808, 843, 853, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 944, 981, 987, 989, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1830, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2181, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2379, 2380, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2888, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3528, 3529, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3888, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4447, 4449, 4550, 4567, 4662, 4712, 4713, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5556, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5984, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6379, 6389, 6443, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7210, 7402, 7435, 7443, 7473, 7474, 7496, 7512, 7574, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8005, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8098, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8301, 8302, 8333, 8383, 8400, 8402, 8443, 8500, 8529, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8983, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9042, 9043, 9050, 9060, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9300, 9415, 9418, 9443, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9990, 9993, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27017, 27018, 27019, 27352, 27353, 27355, 27356, 27715, 28015, 28017, 28201, 29015, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389]
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
    nmap_style_servers_str = " ".join("{0}".format(server[ip_type]) for server in servers)
    nmap_style_ports_str = ",".join("{0}".format(port) for port in PORTS)
    
    scanner = nmap.PortScanner()
    # start scan
    scanner.scan(nmap_style_servers_str, nmap_style_ports_str)
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

# scan server
scan_server(config_data[config_key], ip_type)
############################## EXECUTION <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
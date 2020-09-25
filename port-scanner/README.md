# PORT SCANNER

## About
The `scanner.py` script will scan open ports on server and generate report

## Script positional parameters

1. Path to configuration.yaml file
2. key name of server mapping
3. Scan using private or public IPs
    -  <span style="color: black;background-color: #F9F69A">NOTE: provide IP type, not the IP i.e private_ip | public_ip</span>

## YAML config format

Below is the key/value mapping for config.yaml file

```YAML
slack_api_token: <SLACK API TOKEN>
slack_channel: '<SLACK CHANNEL CODE>'
server_with_ip:
    - name: <name of server>
    public_ip: <public ip>
    private_ip: <private ip>
```

## Usage 

1. Create python virtual enviroment: `python3 -m venv env`
2. Activate the venv: `source env/bin/activate`
3. Install required pip modules: `pip3 install -r requirements.txt`
4. Run the script after changing placeholder text as per requirement:

    `python3 scanner.py </path/to/config>.yaml <key_name_of_server_mapping> <private_ip | public_ip>`

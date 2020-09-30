# UFW Rule Scanner

## About

The `scanner.py` script will scan ufw rules on server and generate report

## Script positional parameters

1. Path to configuration.yaml file
2. key name of server mapping

## YAML config format

Below is the key/value mapping for config.yaml file

```YAML
slack_api_token: <SLACK API TOKEN>
slack_channel: '<SLACK CHANNEL CODE>'
ssh_user: <SSH username>
ssh_key_path: '<SSH private key full path>'
ufw_servers:
    - type: <server category eg. mongodb|postgres|etc>
      expect_rule_for_ports: [<List of allowed ports>]
      servers:
        - name: <Server name>
          ip: <Public IP>
```

## Usage

1. Create python virtual enviroment: `python3 -m venv env`
2. Activate the venv: `source env/bin/activate`
3. Install required pip modules: `pip3 install -r requirements.txt`
4. Run the script after changing placeholder text as per requirement:

    `python3 scanner.py </path/to/config>.yaml <key_name_of_server_mapping>`

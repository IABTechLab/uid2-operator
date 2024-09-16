from flask import Flask
import json
import os

app = Flask(__name__)

@app.route('/getConfig', methods=['GET'])
def get_config():
    try:
        with open('/etc/secret/secret-value/config', 'r') as secret_file:
            secret_value = secret_file.read().strip()
            secret_value_json = json.loads(secret_value)
            secret_value_json["environment"] = secret_value_json["environment"].lower()
            if "core_base_url" in secret_value_json:
                secret_value_json["core_base_url"] = secret_value_json["core_base_url"].lower()
            if "optout_base_url" in secret_value_json:
                secret_value_json["optout_base_url"] = secret_value_json["optout_base_url"].lower()
            if "operator_type" in secret_value_json and secret_value_json["operator_type"].lower() == "public":
                mount_path = '/etc/config/config-values'
                if os.path.exists(mount_path):
                    config_keys = [f for f in os.listdir(mount_path) if os.path.isfile(os.path.join(mount_path, f))]
                    config = {}
                    for k in config_keys:
                        with open(os.path.join(mount_path, k), 'r') as value:
                            config[k] = value.read()
                            if config[k] in ['true', 'false']:
                                config[k] = bool(config[k])
                            elif config[k].isdigit():
                                config[k] = int(config[k])
                            else:
                                try:
                                    float(config[k])
                                    config[k] = float(config[k])
                                except Exception:
                                    pass
                    secret_value_json.update(config)
        return json.dumps(secret_value_json)
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(processes=8)

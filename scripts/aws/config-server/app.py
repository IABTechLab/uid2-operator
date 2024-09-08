from flask import Flask
import json

app = Flask(__name__)

@app.route('/getConfig', methods=['GET'])
def get_config():
    try:
        with open('/etc/secret/secret-value/config', 'r') as secret_file:
            secret_value = secret_file.read().strip()
            secret_value_json = json.loads(secret_value)
            secret_value_json["environment"] = secret_value_json["environment"].lower()
            if secret_value_json["core_base_url"] is not None:
                secret_value_json["core_base_url"] = secret_value_json["core_base_url"].lower()
            if secret_value_json["optout_base_url"] is not None:
                secret_value_json["optout_base_url"] = secret_value_json["optout_base_url"].lower()
        return json.dumps(secret_value_json)
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(processes=8)

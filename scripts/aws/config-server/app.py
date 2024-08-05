import requests
from flask import Flask

app = Flask(__name__)

@app.route('/getConfig', methods=['GET'])
def get_config():
    try:
        with open('/etc/secret/secret-value/config', 'r') as secret_file:
            secret_value = secret_file.read().strip()
        return secret_value
    except Exception as e:
        try:
            token = requests.put("http://169.254.169.254/latest/api/token", headers={"X-aws-ec2-metadata-token-ttl-seconds": "3600"})
            user_data = requests.get("http://169.254.169.254/latest/user-data", headers={"X-aws-ec2-metadata-token": token.text})
            return user_data.text
        except Exception as e:
            return str(e), 500

if __name__ == '__main__':
    app.run(processes=8)

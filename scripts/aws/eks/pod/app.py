from flask import Flask

app = Flask(__name__)

@app.route('/getConfig', methods=['GET'])
def get_config():
    try:
        with open('/etc/secret/secret-value', 'r') as secret_file:
            secret_value = secret_file.read().strip()
        return secret_value
    except Exception as e:
        return str(e), 500

if __name__ == '__main__':
    app.run(processes=8)

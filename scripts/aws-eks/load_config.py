import json
import requests

def get_secret(key):
    res = requests.get("http://operator-config-service.uid-test.svc.cluster.local/operator/" + key)
    return res.text

def get_config():
    result = {
        "api_token": get_secret("API_TOKEN"),
        "environment": get_config("UID2_ENVIRONMENT"),
    }
    print(json.dumps(result))

get_config()

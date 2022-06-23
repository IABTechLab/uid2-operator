import json
import sys


def load_json(path):
  with open(path, 'r') as f:
    return json.load(f)


def apply_override(config, overrides, key, type):
  value = overrides.get(key)
  if value is not None:
    config[key] = type(value)


config_path = sys.argv[1]
overrides_path = sys.argv[2]
thread_count = int(sys.argv[3])

config = load_json(config_path)
overrides = load_json(overrides_path)

# set API key
config['core_api_token'] = overrides['api_token']
config['optout_api_token'] = overrides['api_token']

# number of threads
config['service_instances'] = thread_count

# allowed overrides
apply_override(config, overrides, 'loki_enabled', int)
apply_override(config, overrides, 'optout_synthetic_logs_enabled', bool)
apply_override(config, overrides, 'optout_synthetic_logs_count', int)

# environment
if overrides.get('environment') == 'integ':
  config['clients_metadata_path'] = 'https://core-integ.uidapi.com/clients/refresh'
  config['keys_metadata_path'] = 'https://core-integ.uidapi.com/key/refresh'
  config['keys_acl_metadata_path'] = 'https://core-integ.uidapi.com/key/acl/refresh'
  config['salts_metadata_path'] = 'https://core-integ.uidapi.com/salt/refresh'
  config['optout_metadata_path'] = 'https://optout-integ.uidapi.com/optout/refresh'
  config['core_attest_url'] = 'https://core-integ.uidapi.com/attest'
  config['optout_api_uri'] = 'https://optout-integ.uidapi.com/optout/replicate'
  config['optout_s3_folder'] = 'uid2-optout-integ/'

print(json.dumps(config))

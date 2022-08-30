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
integ_config_path = sys.argv[2]
overrides_path = sys.argv[3]
thread_count = int(sys.argv[4])

config = load_json(config_path)
overrides = load_json(overrides_path)

# set API key
config['core_api_token'] = overrides['api_token']
config['optout_api_token'] = overrides['api_token']

# number of threads
config['service_instances'] = thread_count

# allowed overrides
apply_override(config, overrides, 'loki_enabled', bool)
apply_override(config, overrides, 'optout_synthetic_logs_enabled', bool)
apply_override(config, overrides, 'optout_synthetic_logs_count', int)

# environment
if overrides.get('environment') == 'integ':
  integ_config = load_json(integ_config_path)
  apply_override(integ_config, overrides, 'clients_metadata_path', str)
  apply_override(integ_config, overrides, 'keys_metadata_path', str)
  apply_override(integ_config, overrides, 'keys_acl_metadata_path', str)
  apply_override(integ_config, overrides, 'salts_metadata_path', str)
  apply_override(integ_config, overrides, 'optout_metadata_path', str)
  apply_override(integ_config, overrides, 'core_attest_url', str)
  apply_override(integ_config, overrides, 'optout_api_uri', str)
  apply_override(integ_config, overrides, 'optout_s3_folder', str)

print(json.dumps(config))

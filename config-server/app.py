from flask import Flask
 
app = Flask(__name__)
 
@app.route('/getConfig', methods=['GET'])
def get_config():
    # TODO: Figure out how to get kube secrets from k8 in python
    return "kat-test"
 
if __name__ == '__main__':
    app.run(processes=8)

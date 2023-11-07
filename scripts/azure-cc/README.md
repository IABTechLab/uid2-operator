# UID2 Operator - Azure Confidential Container package

## Generate Deployment Artifacts

Generate deployment files by following command.

```
IMAGE={IMAGE} OUTPUT_DIR=output ./generate-deployment-artifacts.sh
```
Following files will be generated:

* Deployment files will be stored to directory `output`
  * `operator-digest.txt`: the digest will be used as enclave ID to be registered in admin portal.
  * Other files are used to deploy to Azure as described in the next section.
* Deployment files will also be archived into file `output/uid2-operator-deployment-artifacts.zip`

## Deploy

Create a resource group for running the UID2 Operator
  
```
az deployment group create -g {RESOURCE_GROUP_NAME} --location {LOCATION}
```

Once resource group is created, you can create the networking required. This is optional if you need to use your existing network. However it is recommend. 

```
az deployment group create --name vnet --resource-group {RESOURCE_GROUP_NAME} --template-file vnet.json
```

Now, create vault to store the operator key, and the identity to run operator 

```
az deployment group create --name vault --resource-group {RESOURCE_GROUP_NAME} --parameters vault.parameters.json  --template-file vault.json
```

Create the operator containers now. 
 
```
az deployment group create --name operator --resource-group {RESOURCE_GROUP_NAME} --parameters operator.parameters.json  --template-file operator.json
```

Since the operators are created in private subnet, we need a public IP. Copy the container IP of the created containers running operators to `gateway.parameters.json` and run

```
az deployment group create --name gateway --resource-group {RESOURCE_GROUP_NAME} --parameters gateway.parameters.json  --template-file gateway.json
```

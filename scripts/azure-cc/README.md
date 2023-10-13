# UID2 Operator - Azure Confidential Container package

## Generate CCE policy

Note: only `deploymentEnvironment` and `image` need to be specified. Other empty parameters are wildcards.

```
az confcom acipolicygen -a arm-template.json -p template-policy.parameters.json --approve-wildcards -y --debug-mode
```

## Deploy

```
RESOURCE_GROUP=uid-enclave-test
az deployment group create --resource-group $RESOURCE_GROUP --name rollout \
    --template-file arm-template.json  \
    --parameters @template.parameters.json
```
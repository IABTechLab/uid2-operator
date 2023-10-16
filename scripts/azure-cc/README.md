# UID2 Operator - Azure Confidential Container package

## Generate CCE policy

Note: only `deploymentEnvironment` and `image` need to be specified. Other empty parameters are wildcards.

```
az confcom acipolicygen -a arm-template.json -p template-policy.parameters.json --approve-wildcards -y --debug-mode
```

## Deploy

```
az deployment group create -g {RESOURCE_GROUP_NAME} -n rollout \
    --template-file arm-template.json  \
    --parameters @template.parameters.json
```

## How to set up azure vault & managed identity
Create a user-assigned managed identity
```
az identity create -g {RESOURCE_GROUP_NAME} -n {IDENTITY_NAME}
```

Create key vault
```
az keyvault create -g {RESOURCE_GROUP_NAME} -n {VAULT_NAME}
```

Create a secret (if one doesn't exist) or update a secret in a KeyVault.
```
az keyvault secret set -n {SECRET_NAME} --vault-name {VAULT_NAME} --value {SECRET_VALUE}
```

Grant vault permission
 - get security principal id of the managed identity first,
 - then grant read permission
```
SP_ID=$(az identity show \
  -g {RESOURCE_GROUP_NAME} \
  -n {IDENTITY_NAME} \
  --query principalId --output tsv)
az keyvault set-policy \
   -g {RESOURCE_GROUP_NAME} \
   -n {VAULT_NAME} \
   --object-id $SP_ID \
   --secret-permissions get
```
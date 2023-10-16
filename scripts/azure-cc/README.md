# UID2 Operator - Azure Confidential Container package

## Generate CCE policy

Generate deployment files by following command.

```
IMAGE={IMAGE} ./generate-deployment-artifacts.sh
```
Following files will be generated:

* `deployment-template-with-policy.json`: to be used for deployment
* `deployment-digest.txt`: the digest will be used as enclave ID to be registered in admin portal.

## Deploy
Update `deployment-parameters.json` to set deployment parameters, then deploy via following command.

```
az deployment group create -g {RESOURCE_GROUP_NAME} -n rollout \
    --template-file deployment-template-with-policy.json  \
    --parameters @deployment-parameters.json
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

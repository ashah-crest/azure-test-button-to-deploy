targetScope = 'resourceGroup'

// ------------- Parameters -------------

@minLength(1)
@maxLength(8)
@description('Base prefix for naming (no spaces)')
param appName string

@secure()
@description('Google Threat Intelligence (GTI) API Key')
param gtiApiKey string = '8f3d691e940119a932e2a374c71d16dd31ad5c866410704b71df8a9a9455c670'

@description('Comma-separated GTI threat list categories (empty for all)')
param threatLists string = 'ransomware'

@description('Historical lookback period upto 7 days for initial sync (Default 7)')
param lookBackDays string = '1'

@description('(Optional) Comma-separated GTI Verdict level(s) from VERDICT_BENIGN, VERDICT_UNDETECTED, VERDICT_SUSPICIOUS, VERDICT_UNKNOWN & empty for all')
param verdicts string = ''

@description('(Optional) Comma-separated GTI Severity level(s) from SEVERITY_NONE, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_UNKNOWN & empty for all')
param severities string = ''

@description('Minimum GTI Threat Score')
param threatScore string = '60'

@description('CRON expression for scheduling (default hourly)')
param timerSchedule string = '0 */5 * * * *'

@description('Object ID of deploying user for Key Vault access')
param currentUserObjectId string = '92c5470a-1222-4df9-8a67-f905b0e81f91'

@description('MS Defender Application Client ID')
param appClientID string = '091029b1-c795-47c7-9e7a-b27dabf27e53'

@secure()
@description('MS Defender Application Client Secret')
param appClientSecret string = 'qTI8Q~qyWv6eR-e9McobQvACFAFA-_cYB45SWaNc'

@description('MS Defender Application Tenant ID')
param appTenantId string = '3adb963c-8e61-48e8-a06d-6dbb0dacea39'

var functionPackageUrl string = 'https://raw.githubusercontent.com/ashah-crest/azure-test-button-to-deploy/main/host.zip'


// ------------- Variables -------------

var tenantId = tenant().tenantId
var location = resourceGroup().location

var storageAccountName = toLower('${appName}sa${uniqueString(resourceGroup().id)}')
var deploymentContainerName = toLower('${appName}-container')
var hostingPlanName = '${appName}-plan'
var functionAppName = '${appName}-func'
var appInsightsName = '${appName}-ai'
var keyVaultName = '${appName}-kv'
var deploymentScriptName = '${appName}-ds'

var checkpointTableName = 'ApiCheckpoints'
var failedIOCsTableName = 'FailedIOCs'

var storageTableContributor string = '/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'


// ------------- Resource Definitions -------------

//User Assigned Identity for the script to "talk" to Azure
resource scriptIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-identity'
  location: location
}

var storageBlobDataOwnerRoleId  = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageBlobDataContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'

resource roleAssignmentBlobDataOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storageAccount.id, scriptIdentity.id, 'Storage Blob Data Owner')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: scriptIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource roleAssignmentBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, storageAccount.id, scriptIdentity.id, 'Storage Blob Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataContributorRoleId)
    principalId: scriptIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Deployment Script:To Validate Parameters
// resource validateParameters 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
//   name: deploymentScriptName
//   location: location
//   kind: 'AzureCLI'
//   identity: {
//     type: 'UserAssigned'
//     userAssignedIdentities: {
//       '${scriptIdentity.id}': {}
//     }
//   }
//   properties: {
//     azCliVersion: '2.52.0'
//     timeout: 'PT5M'
//     cleanupPreference: 'OnSuccess'  // deletes script resource after success
//     retentionInterval: 'P1D'
//     forceUpdateTag: deploymentScriptName      // ensures script runs every deployment

//     environmentVariables: [
//       { name: 'THREAT_INPUT', value: threatLists }
//       { name: 'SEV_INPUT', value: severities }
//       { name: 'VERDICT_INPUT', value: verdicts }
//     ]

//     scriptContent: '''
//       # Allowed Lists (Space-separated for easy Bash looping)
//       allowedT="ransomware malicious-network-infrastructure malware threat-actor trending mobile osx linux iot cryptominer phishing first-stage-delivery-vectors vulnerability-weaponization infostealer"
//       allowedS="SEVERITY_NONE SEVERITY_LOW SEVERITY_MEDIUM SEVERITY_HIGH SEVERITY_UNKNOWN"
//       allowedV="VERDICT_BENIGN VERDICT_UNDETECTED VERDICT_SUSPICIOUS VERDICT_UNKNOWN"

//       invalid=()

//       # Validation Logic
//       # Replacing commas with spaces to let Bash iterate naturally
      
//       # Validating Threat Lists
//       for val in ${THREAT_INPUT//,/ }; do
//         if [[ ! $allowedT =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
//           invalid+=("threatLists:$val")
//         fi
//       done

//       # Validating Severities
//       for val in ${SEV_INPUT//,/ }; do
//         if [[ ! $allowedS =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
//           invalid+=("severities:$val")
//         fi
//       done

//       # Validating Verdicts
//       for val in ${VERDICT_INPUT//,/ }; do
//         if [[ ! $allowedV =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
//           invalid+=("verdicts:$val")
//         fi
//       done

//       # 3. Final Check
//       if [ ${#invalid[@]} -gt 0 ]; then
//         echo "ERROR: The following inputs are invalid: ${invalid[*]}" >&2
//         exit 1
//       fi

//       echo "All parameters validated successfully."      
//     '''
//   }
// }

// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    dnsEndpointType: 'Standard'
    minimumTlsVersion: 'TLS1_2'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
    }
    publicNetworkAccess: 'Enabled'
  }
  resource blobServices 'blobServices' = {
    name: 'default'
    properties: {
      deleteRetentionPolicy: {}
    }
    resource deploymentContainer 'containers' = {
      name: deploymentContainerName
      properties: {
        publicAccess: 'None'
      }
    }
  }
  // dependsOn: [ validateParameters ]
}

// Tables
resource checkpointTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = {
  name: '${storageAccount.name}/default/${checkpointTableName}'
}
resource failedIOCsTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = {
  name: '${storageAccount.name}/default/${failedIOCsTableName}'
}

// Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: { Application_Type: 'web' }
  // dependsOn: [ validateParameters ]
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: { name: 'standard', family: 'A' }
    enableRbacAuthorization: false
    accessPolicies: []
  }
  // dependsOn: [ validateParameters ]
}

// Store API token as a KeyVault secret
resource keyVaultSecret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'gti-api-token'
  properties: { value: gtiApiKey }
}

resource clientId 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'app-client-id'
  properties: { value: appClientID }
}

resource clientSecret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'app-client-secret'
  properties: { value: appClientSecret }
}

resource applicationTenantId 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'app-tenant-id'
  properties: { value: appTenantId }
}

// App Service Plan (Consumption)
// resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
//   name: hostingPlanName
//   location: location
//   kind: 'linux'
//   sku: { name: 'Y1', tier: 'Dynamic' }
//   properties: { reserved: true }
// }
resource hostingPlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: hostingPlanName
  location: location
  kind: 'linux'
  sku: {
    tier: 'FlexConsumption'
    name: 'FC1'
  }
  properties: {
    reserved: true
  }
}

// var storageConnString = 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'

// Function App (Consumption)
resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    functionAppConfig: {
      runtime: {
        name: 'java'
        version: '17'
      }
      scaleAndConcurrency: {
        instanceMemoryMB: 512
        maximumInstanceCount: 1
      }
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccount.properties.primaryEndpoints.blob}${deploymentContainerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: scriptIdentity.id
          }
        }
      }
    }
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccount.name
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        // configuration
        {
          name: 'LOOKBACK_DAYS'
          value: lookBackDays
        }
        {
          name: 'THREAT_LISTS'
          value: threatLists
        }
        {
          name: 'SEVERITY_LEVELS'
          value: severities
        }
        {
          name: 'VERDICT_LEVELS'
          value: verdicts
        }
        {
          name: 'GTI_SCORE'
          value: threatScore
        }

        // ---- Scheduling ----
        {
          name: 'TIMER_SCHEDULE'
          value: timerSchedule
        }

        // ---- Key Vault ----
        {
          name: 'KEYVAULT_URI'
          value: keyVault.properties.vaultUri
        }

        // ---- Table Storage ----
        {
          name: 'CHECKPOINT_TABLE_NAME'
          value: checkpointTableName
        }
        {
          name: 'FAILED_IOC_TABLE_NAME'
          value: failedIOCsTableName
        }
        {
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccount.name
        }
        {
          name: 'CLIENT_ID'
          value: appClientID
        }
        {
          name: 'CLIENT_SECRET'
          value: appClientSecret
        }
        {
          name: 'APPLICATION_ID'
          value: appTenantId
        }
      ]
    }
    httpsOnly: true
  }
  dependsOn: [ 
    // validateParamters 
  ]
}

// The OneDeploy Extension
resource zipDeploy 'Microsoft.Web/sites/extensions@2023-12-01' = {
  parent: functionApp
  name: 'onedeploy'
  properties: {
    packageUri: functionPackageUrl
  }
  dependsOn:[
    roleAssignmentBlobDataOwner
    roleAssignmentBlob
  ]
}

// resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
//   name: guid(scriptIdentity.id, 'contributor', resourceGroup().id)
//   scope: resourceGroup() 
//   properties: {
//     // Contributor Role ID
//     roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c') 
//     principalId: scriptIdentity.properties.principalId
//     principalType: 'ServicePrincipal'
//   }
// }

// resource zipUploadScript 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
//   name: '${appName}-zip-copy-ds'
//   location: location
//   kind: 'AzureCLI'
//   identity: {
//     type: 'UserAssigned'
//     userAssignedIdentities: {
//       '${scriptIdentity.id}': {}
//     }
//   }
//   dependsOn: [
//     functionApp
//     roleAssignment
//   ]
//   properties: {
//     azCliVersion: '2.59.0'
//     timeout: 'PT10M'
//     retentionInterval: 'P1D'
//     environmentVariables: [
//       { name: 'ZIP_URL', value: functionPackageUrl } // Pass your public ZIP URL here
//       { name: 'STORAGE_ACCOUNT', value: storageAccount.name }
//       { name: 'APP_NAME', value: functionAppName }
//       { name: 'RG_NAME', value: resourceGroup().name }
//       { name: 'SUB_ID', value: subscription().subscriptionId }
//     ]
//     scriptContent: '''
//       # 1. Exit immediately if a command exits with a non-zero status
//       set -e

//       # 1. Force the CLI to use the correct subscription
//       echo "Setting context to subscription: $SUB_ID"
//       az account set --subscription "$SUB_ID"

//       echo "Starting deployment process..."

//       # 2. Use wget instead of curl (more common in CLI images)
//       # -O deployment.zip saves the file
//       if ! wget -q $ZIP_URL -O deployment.zip; then
//         echo "ERROR: wget failed to download the zip from $ZIP_URL" >&2
//         exit 1
//       fi

//       # 3. Check if file actually exists and has size
//       if [ ! -s deployment.zip ]; then
//         echo "ERROR: Downloaded zip file is empty or missing." >&2
//         exit 1
//       fi

//       echo "Pushing ZIP to Function App: $APP_NAME in RG: $RG_NAME"

//       # 4. Deploy using the CLI's native zip deploy command
//       # Adding --async can help prevent timeouts for large zips
//       az functionapp deployment source config-zip \
//         --resource-group "$RG_NAME" \
//         --name "$APP_NAME" \
//         --src deployment.zip \
//         --verbose

//       echo "Deployment successfully triggered."
//     '''
//   }
// }

// Give the function app access to Key Vault secrets
resource keyVaultPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2024-11-01' = {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: tenantId
        objectId: functionApp.identity.principalId
        permissions: { secrets: [ 'get', 'list' ] }
      }
      {
        tenantId: tenantId
        objectId: currentUserObjectId
        permissions: { secrets: [ 'get', 'list', 'set', 'delete' ] }
      }
    ]
  }
}


// Storage role assignment for table access
resource tableStorageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, 'table-access')
  scope: storageAccount
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: storageTableContributor
  }
}


/* -------------------- Outputs -------------------- */
output functionAppName string = functionApp.name
output keyVaultName string = keyVault.name
output storageAccountName string = storageAccount.name
output checkpointTable string = checkpointTableName

targetScope = 'resourceGroup'

@description('Tenant ID of your Azure subscription (Default: Logged-in Tenant)')
var tenantId string = tenant().tenantId

@description('Location for all resources')
var location string = resourceGroup().location

@description('Base application name')
param appName string

@description('Public URL of the ZIP package containing the Java Function')
param functionPackageUrl string = 'https://raw.githubusercontent.com/ashah-crest/azure-test-button-to-deploy/main/host.zip'

var storageTableContributor string = '/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'

@description('Comma-separated GTI threat list categories (empty for all)')
param threatLists string = ''

@description('Historical lookback period upto 7 days for initial sync (Default 7)')
param lookBackDays string

@description('Comma-separated GTI verdict level(s) from "VERDICT_BENIGN","VERDICT_UNDETECTED","VERDICT_SUSPICIOUS","VERDICT_UNKNOWN" & empty for all')
param verdicts string = ''

@description('Comma-separated GTI Severity level(s) from "SEVERITY_NONE", "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_UNKNOWN" & empty for all')
param severities string = ''

@description('Minimum GTI Threat Score')
param threatScore string = ''

@description('Google Threat Intelligence (GTI) API key')
@secure()
param gtiApiToken string

@description('CRON expression for Scheduling, default set to every 1 hour ')
param timerSchedule string = '0 */1 * * *'

@description('Object ID of the Azure AD user executing the template to provide access to Key Vault')
param currentUserObjectId string = ''

@description('Checkpoint table name')
var checkpointTableName string = 'ApiCheckpoints'

@description('Failed IOCs table name')
var failedIOCsTableName string = 'FailedIOCs'

@description('MS Defender Application Client ID')
param clientID string

@secure()
@description('MS Defender Application Client Secret')
param clientSecret string

@description('MS Defender Application ID')
param applicationID string

//User Assigned Identity for the script to "talk" to Azure
resource scriptIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'val-identity'
  location: location
}

// ===============================
// Deployment SCRIPT:To Validate Parameters and Fetch Current User Object ID
// ===============================
resource validateAndLookup 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: 'validateGtiParams'
  location: location
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${scriptIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.52.0'
    timeout: 'PT5M'
    cleanupPreference: 'OnSuccess'  // deletes script resource after success
    retentionInterval: 'P1D'
    forceUpdateTag: 'validateGtiParamsTag'      // ensures script runs every deployment

    environmentVariables: [
      { name: 'THREAT_INPUT', value: threatLists }
      { name: 'SEV_INPUT', value: severities }
      { name: 'VERDICT_INPUT', value: verdicts }
    ]

    scriptContent: '''
      # Allowed Lists (Space-separated for easy Bash looping)
      allowedT="ransomware malicious-network-infrastructure malware threat-actor trending mobile osx linux iot cryptominer phishing first-stage-delivery-vectors vulnerability-weaponization infostealer"
      allowedS="SEVERITY_NONE SEVERITY_LOW SEVERITY_MEDIUM SEVERITY_HIGH SEVERITY_UNKNOWN"
      allowedV="VERDICT_BENIGN VERDICT_UNDETECTED VERDICT_SUSPICIOUS VERDICT_UNKNOWN"

      invalid=()

      # Validation Logic
      # Replacing commas with spaces to let Bash iterate naturally
      
      # Validating Threat Lists
      for val in ${THREAT_INPUT//,/ }; do
        if [[ ! $allowedT =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
          invalid+=("threatLists:$val")
        fi
      done

      # Validating Severities
      for val in ${SEV_INPUT//,/ }; do
        if [[ ! $allowedS =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
          invalid+=("severities:$val")
        fi
      done

      # Validating Verdicts
      for val in ${VERDICT_INPUT//,/ }; do
        if [[ ! $allowedV =~ (^|[[:space:]])"$val"($|[[:space:]]) ]]; then
          invalid+=("verdicts:$val")
        fi
      done

      # 3. Final Check
      if [ ${#invalid[@]} -gt 0 ]; then
        echo "ERROR: The following inputs are invalid: ${invalid[*]}" >&2
        exit 1
      fi

      echo "All parameters validated successfully."

      # To get the Object ID of the user currently deploying via the Portal/CLI
      USER_ID=$(az ad signed-in-user show --query id -o tsv)

      echo "{\"userObjectId\": \"$USER_ID\"}" > $AZ_SCRIPTS_OUTPUT_PATH
      
    '''
  }
}


var storageAccountName = toLower('${appName}sa${uniqueString(resourceGroup().id)}')
var functionAppName = '${appName}-func'
var appInsightsName = '${appName}-ai'
var keyVaultName = '${appName}-kv'

/* -------------------- Storage Account -------------------- */
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  dependsOn: [
    validateAndLookup
  ]
}

/* -------------------- Table Storage -------------------- */
resource checkpointTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = {
  name: '${storageAccount.name}/default/${checkpointTableName}'
}

resource failedIOCsTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = {
  name: '${storageAccount.name}/default/${failedIOCsTableName}'
}

/* -------------------- Application Insights -------------------- */
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  dependsOn: [
    validateAndLookup
  ]
}

/* -------------------- Key Vault -------------------- */
resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    enableRbacAuthorization: false
    accessPolicies: []
  }
  dependsOn: [
    validateAndLookup
  ]
}

/* -------------------- Key Vault Secret -------------------- */
resource keyVaultSecret 'Microsoft.KeyVault/vaults/secrets@2024-11-01' = {
  parent: keyVault
  name: 'GtiApiToken'
  properties: {
    value: gtiApiToken
  }
}

resource hostingPlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${appName}-plan'
  location: location
  kind: 'linux'
  sku: { name: 'Y1', tier: 'Dynamic' }
  properties: { reserved: true }
}

/* -------------------- Function App (Consumption) -------------------- */
resource functionApp 'Microsoft.Web/sites@2024-11-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    siteConfig: {
      linuxFxVersion: 'JAVA|17'
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
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'java'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: functionPackageUrl
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
          value: clientID
        }
        {
          name: 'CLIENT_SECRET'
          value: clientSecret
        }
        {
          name: 'APPLICATION_ID'
          value: applicationID
        }
      ]
    }
    httpsOnly: true
  }
  dependsOn: [
    validateAndLookup
  ]
}

/* -------------------- Key Vault Access Policy -------------------- */
resource keyVaultPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2024-11-01' = {
  parent: keyVault
  name: 'add'
  properties: {
    accessPolicies: [
      {
        tenantId: tenantId
        objectId: functionApp.identity.principalId
        permissions: {
          secrets: [
            'get'
            'list'
          ]
        }
      }
      {
        tenantId: tenantId
        objectId: validateAndLookup.properties.outputs.userObjectId
        permissions: {
          secrets: ['get','list','set','delete']
        }
      }
    ]
  }
}


/* -------------------- Table Storage RBAC -------------------- */
resource tableStorageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, 'table-access')
  scope: storageAccount
  properties: {
    principalId: functionApp.identity.principalId
    roleDefinitionId: storageTableContributor
  }
}

// resource appReg 'Microsoft.Graph/applications@1.0-preview' = {
//   name: 'defender-ioc-app'
//   properties: {
//     displayName: 'Defender IOC Ingestion App'
//     signInAudience: 'AzureADMyOrg'
//   }
// }

// resource sp 'Microsoft.Graph/servicePrincipals@1.0' = {
//   name: appReg.properties.appId
//   properties: {
//     appId: appReg.properties.appId
//   }
// }

/* -------------------- Outputs -------------------- */
// output functionAppName string = functionApp.name
output keyVaultName string = keyVault.name
output storageAccountName string = storageAccount.name
output checkpointTable string = checkpointTableName

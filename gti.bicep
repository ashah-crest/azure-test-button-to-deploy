targetScope = 'resourceGroup'

@description('Tenant ID of your Azure subscription (Default: Logged-in Tenant)')
param tenantId string = tenant().tenantId

@description('Location for all resources')
param location string = resourceGroup().location

@description('Base application name')
param appName string

@description('Public URL of the ZIP package containing the Java Function')
param functionPackageUrl string

param storageTableContributor string = '/providers/Microsoft.Authorization/roleDefinitions/0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'

@description('Comma-separated GTI threat list categories (empty for all)')
param threatLists string = ''

@description('Historical lookback period in days for initial sync (max 7)')
param lookBackDays string = '7'

@description('Comma-separated GTI verdict level(s) from "VERDICT_BENIGN","VERDICT_UNDETECTED","VERDICT_SUSPICIOUS","VERDICT_UNKNOWN" & empty for all')
param verdicts string = ''

@description('Comma-separated GTI Severity level(s) from "SEVERITY_NONE", "SEVERITY_LOW", "SEVERITY_MEDIUM", "SEVERITY_HIGH", "SEVERITY_UNKNOWN" & empty for all')
param severities string = ''

@description('Minimum GTI Threat Score')
param threatScore string = ''

@description('Google Threat Intelligence (GTI) API key')
@secure()
param gtiApiToken string

@description('Timer CRON expression passed via CLI')
param timerSchedule string

@description('Object ID of the Azure AD user executing the template to provide access to Key Vault')
param currentUserObjectId string = ''

@description('Checkpoint table name')
param checkpointTableName string = 'ApiCheckpoints'


/* -------------------- Names -------------------- */
var storageAccountName = toLower('${appName}sa${uniqueString(resourceGroup().id)}')
var functionAppName = '${appName}-func'
var appInsightsName = '${appName}-ai'
var keyVaultName = '${appName}-kv'

/* -------------------- User Assigned Managed Identity -------------------- */
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-kv-defender-identity'
  location: location
}

/* -------------------- Storage Account -------------------- */
resource storageAccount 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
}

/* -------------------- Table Storage -------------------- */
resource checkpointTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2025-01-01' = {
  name: '${storageAccount.name}/default/${checkpointTableName}'
}

/* -------------------- Application Insights -------------------- */
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
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
          name: 'STORAGE_ACCOUNT_NAME'
          value: storageAccount.name
        }
        {
          name: 'CLIENT_ID'
          value: '091029b1-c795-47c7-9e7a-b27dabf27e53'
        }
        {
          name: 'CLIENT_SECRET'
          value: 'qTI8Q~qyWv6eR-e9McobQvACFAFA-_cYB45SWaNc'
        }
        {
          name: 'APPLICATION_ID'
          value: '3adb963c-8e61-48e8-a06d-6dbb0dacea39'
        }
      ]
    }
    httpsOnly: true
  }
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
        objectId: uami.properties.principalId
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

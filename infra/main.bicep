// =============================================================================
// CodeRunner - True One-Click Deployment
// =============================================================================
//
// Click "Deploy to Azure" → Select subscription/resource group → Done!
//
// Features:
// - Managed Identity for secure storage access (no shared keys)
// - Auto-deploys code from GitHub release (no CLI needed)
// - Zero configuration required
//
// =============================================================================

@description('Location for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

var resourceToken = toLower(uniqueString(resourceGroup().id))
var functionAppName = 'coderunner-${resourceToken}'
var storageAccountName = 'st${resourceToken}'
var appServicePlanName = 'asp-${resourceToken}'
var logAnalyticsName = 'log-${resourceToken}'
var appInsightsName = 'ai-${resourceToken}'

var tags = {
  project: 'code-runner'
}

// Role definition IDs
var storageBlobDataOwnerRoleId = 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
var storageAccountContributorRoleId = '17d1049b-9a84-46fb-8f53-869881c3d3ab'
var storageFileDataPrivilegedContributorRoleId = '69566ab7-960f-475b-8e7c-b3118f30c6bd'

// Deployment package URL
var deployPackageUrl = 'https://github.com/dembaatmicrosoft/code_runner/releases/download/v1.0.0/deploy.zip'

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

// 0. User-Assigned Managed Identity for deployment script
resource deploymentIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-deploy-${resourceToken}'
  location: location
  tags: tags
}

// 1. Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// 2. Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// 3. Storage Account (uses subscription defaults for security settings)
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    accessTier: 'Hot'
  }
}

// 4. App Service Plan (Flex Consumption)
resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  kind: 'functionapp'
  properties: {
    reserved: true
  }
}

// 5. Function App with System-Assigned Managed Identity (Flex Consumption)
resource functionApp 'Microsoft.Web/sites@2024-04-01' = {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    reserved: true
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      appSettings: [
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storageAccount.name
        }
      ]
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storageAccount.properties.primaryEndpoints.blob}deployments'
          authentication: {
            type: 'SystemAssignedIdentity'
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 100
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.11'
      }
    }
  }
  dependsOn: [
    deployCode
  ]
}

// 5b. Blob container for deployment packages
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
}

resource deploymentContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobService
  name: 'deployments'
}

// 5c. Role assignment for deployment script identity
resource deployIdentityBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, deploymentIdentity.id, storageBlobDataOwnerRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: deploymentIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// 5d. Deployment script to upload code package to blob storage
resource deployCode 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'deploy-code-${resourceToken}'
  location: location
  tags: tags
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${deploymentIdentity.id}': {}
    }
  }
  properties: {
    azCliVersion: '2.50.0'
    timeout: 'PT10M'
    retentionInterval: 'PT1H'
    environmentVariables: [
      { name: 'STORAGE_ACCOUNT', value: storageAccount.name }
      { name: 'CONTAINER_NAME', value: 'deployments' }
      { name: 'PACKAGE_URL', value: deployPackageUrl }
    ]
    scriptContent: '''
      # Download package from GitHub
      curl -sL "$PACKAGE_URL" -o /tmp/deploy.zip

      # Get access token for storage using managed identity
      TOKEN=$(az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv)

      # Upload using REST API (avoids shared key auth entirely)
      curl -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "x-ms-version: 2020-04-08" \
        -H "x-ms-blob-type: BlockBlob" \
        -H "Content-Type: application/zip" \
        --data-binary @/tmp/deploy.zip \
        "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER_NAME}/deploy.zip"
    '''
  }
  dependsOn: [
    deploymentContainer
    deployIdentityBlobRole
  ]
}

// 6. Role Assignments for Function App to access Storage
resource storageBlobDataOwnerRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageBlobDataOwnerRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataOwnerRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageAccountContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageAccountContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageAccountContributorRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource storageFileDataContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, functionApp.id, storageFileDataPrivilegedContributorRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageFileDataPrivilegedContributorRoleId)
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Outputs - These appear in Azure Portal after deployment completes
// ---------------------------------------------------------------------------

@description('The API endpoint. POST your Python scripts here.')
output apiEndpoint string = 'https://${functionApp.properties.defaultHostName}/api/run'

@description('Test command. Copy and run in your terminal.')
output testCommand string = 'curl -X POST "https://${functionApp.properties.defaultHostName}/api/run" -H "Content-Type: application/json" -d \'{"script": "print(1+1)"}\''

@description('Function App resource name for Azure CLI commands.')
output functionAppName string = functionApp.name

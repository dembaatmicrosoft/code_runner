// =============================================================================
// CodeRunner Infrastructure - One-Click Deployment Template
// =============================================================================
//
// Deploy with the "Deploy to Azure" button - no CLI required!
//
// Resources provisioned:
//   - Storage Account (for function app state)
//   - App Service Plan (Consumption tier - FREE)
//   - Function App (Python 3.11, Linux)
//   - Application Insights (for monitoring)
//   - Log Analytics Workspace (for logs)
//
// Cost: $0/month within free tier limits
//   - 1,000,000 executions/month free
//   - 400,000 GB-s compute time/month free
//
// =============================================================================

@description('Location for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

var resourceToken = toLower(uniqueString(resourceGroup().id))
var functionAppName = 'coderunner-${resourceToken}'
var storageAccountName = 'crstore${resourceToken}'
var contentShareName = 'coderunner-content'
var appServicePlanName = 'asp-coderunner-${resourceToken}'
var logAnalyticsName = 'log-coderunner-${resourceToken}'
var appInsightsName = 'appi-coderunner-${resourceToken}'

var tags = {
  project: 'code-runner'
  deployedBy: 'one-click-deploy'
}

// ---------------------------------------------------------------------------
// Resources - Defined in dependency order
// ---------------------------------------------------------------------------

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

// 2. Application Insights (depends on Log Analytics)
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

// 3. Storage Account
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
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
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// 4. File Services (depends on Storage Account)
resource fileServices 'Microsoft.Storage/storageAccounts/fileServices@2023-01-01' = {
  parent: storage
  name: 'default'
}

// 5. File Share (depends on File Services)
resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileServices
  name: contentShareName
  properties: {
    shareQuota: 5120
  }
}

// 6. App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: appServicePlanName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

// 7. Function App (explicit dependsOn to ensure storage is fully ready)
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  tags: union(tags, {
    'azd-service-name': 'api'
  })
  kind: 'functionapp,linux'
  dependsOn: [
    fileShare  // Explicit dependency on file share
  ]
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      pythonVersion: '3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${storage.listKeys().keys[0].value};EndpointSuffix=core.windows.net'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${storage.listKeys().keys[0].value};EndpointSuffix=core.windows.net'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: contentShareName
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'ENABLE_ORYX_BUILD'
          value: 'true'
        }
      ]
    }
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

@description('The API endpoint URL. Use this to call your CodeRunner instance.')
output apiEndpoint string = 'https://${functionApp.properties.defaultHostName}'

@description('The name of the deployed Function App.')
output functionAppName string = functionApp.name

@description('The resource group containing all resources.')
output resourceGroupName string = resourceGroup().name

@description('Next step: Deploy your code using Azure Functions Core Tools.')
output nextSteps string = 'Run: func azure functionapp publish ${functionApp.name}'

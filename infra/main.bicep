// =============================================================================
// CodeRunner Infrastructure - Main Bicep Template
// =============================================================================
//
// This template provisions all Azure resources required for CodeRunner:
//   - Resource Group (created at subscription scope)
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

targetScope = 'subscription'

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

@minLength(1)
@maxLength(64)
@description('Name of the environment (e.g., dev, prod). Used for resource naming.')
param environmentName string

@minLength(1)
@description('Azure region for all resources.')
param location string

@description('Name of the Azure Function App. Auto-generated if not provided.')
param functionAppName string = ''

@description('Name of the Storage Account. Auto-generated if not provided.')
param storageAccountName string = ''

@description('Principal ID of the user or service principal deploying the infrastructure.')
param principalId string = ''

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

// Generate unique suffix for resource names
var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

// Resource names with sensible defaults
var abbrs = loadJsonContent('./abbreviations.json')
var tags = {
  'azd-env-name': environmentName
  'project': 'code-runner'
}

// Actual resource names
var actualFunctionAppName = !empty(functionAppName) ? functionAppName : '${abbrs.webSitesFunctions}${resourceToken}'
var actualStorageAccountName = !empty(storageAccountName) ? storageAccountName : '${abbrs.storageStorageAccounts}${resourceToken}'
var appServicePlanName = '${abbrs.webServerFarms}${resourceToken}'
var logAnalyticsName = '${abbrs.operationalInsightsWorkspaces}${resourceToken}'
var appInsightsName = '${abbrs.insightsComponents}${resourceToken}'

// ---------------------------------------------------------------------------
// Resource Group
// ---------------------------------------------------------------------------

resource rg 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

// Log Analytics Workspace for monitoring
module logAnalytics 'modules/log-analytics.bicep' = {
  name: 'logAnalytics'
  scope: rg
  params: {
    name: logAnalyticsName
    location: location
    tags: tags
  }
}

// Application Insights for function monitoring
module appInsights 'modules/app-insights.bicep' = {
  name: 'appInsights'
  scope: rg
  params: {
    name: appInsightsName
    location: location
    tags: tags
    logAnalyticsWorkspaceId: logAnalytics.outputs.id
  }
}

// Storage Account for function app
module storage 'modules/storage.bicep' = {
  name: 'storage'
  scope: rg
  params: {
    name: actualStorageAccountName
    location: location
    tags: tags
  }
}

// App Service Plan (Consumption tier - FREE)
module appServicePlan 'modules/app-service-plan.bicep' = {
  name: 'appServicePlan'
  scope: rg
  params: {
    name: appServicePlanName
    location: location
    tags: tags
    sku: {
      name: 'Y1'
      tier: 'Dynamic'
    }
  }
}

// Function App
module functionApp 'modules/function-app.bicep' = {
  name: 'functionApp'
  scope: rg
  params: {
    name: actualFunctionAppName
    location: location
    tags: tags
    appServicePlanId: appServicePlan.outputs.id
    storageAccountName: storage.outputs.name
    storageAccountKey: storage.outputs.key
    appInsightsConnectionString: appInsights.outputs.connectionString
    appInsightsInstrumentationKey: appInsights.outputs.instrumentationKey
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

@description('The name of the Azure resource group.')
output AZURE_RESOURCE_GROUP string = rg.name

@description('The name of the Azure Function App.')
output AZURE_FUNCTION_APP_NAME string = functionApp.outputs.name

@description('The endpoint URL of the CodeRunner API.')
output SERVICE_API_ENDPOINT_URL string = functionApp.outputs.endpoint

@description('The Azure region where resources are deployed.')
output AZURE_LOCATION string = location

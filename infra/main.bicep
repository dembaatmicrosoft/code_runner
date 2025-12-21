// =============================================================================
// CodeRunner Infrastructure - One-Click Deployment Template
// =============================================================================
//
// Deploy with the "Deploy to Azure" button - no CLI required!
//
// This template provisions all Azure resources required for CodeRunner:
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

// Deploy to the resource group selected in the Azure Portal
// No subscription-level permissions required!

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

@description('Location for all resources. Defaults to the resource group location.')
param location string = resourceGroup().location

// ---------------------------------------------------------------------------
// Variables
// ---------------------------------------------------------------------------

// Generate unique suffix based on resource group - ensures unique names
var resourceToken = toLower(uniqueString(resourceGroup().id))

// Resource naming
var functionAppName = 'coderunner-${resourceToken}'
var storageAccountName = 'crstore${resourceToken}'
var appServicePlanName = 'asp-coderunner-${resourceToken}'
var logAnalyticsName = 'log-coderunner-${resourceToken}'
var appInsightsName = 'appi-coderunner-${resourceToken}'

var tags = {
  project: 'code-runner'
  deployedBy: 'one-click-deploy'
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

// Log Analytics Workspace for monitoring
module logAnalytics 'modules/log-analytics.bicep' = {
  name: 'logAnalytics'
  params: {
    name: logAnalyticsName
    location: location
    tags: tags
  }
}

// Application Insights for function monitoring
module appInsights 'modules/app-insights.bicep' = {
  name: 'appInsights'
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
  params: {
    name: storageAccountName
    location: location
    tags: tags
  }
}

// App Service Plan (Consumption tier - FREE)
module appServicePlan 'modules/app-service-plan.bicep' = {
  name: 'appServicePlan'
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
  params: {
    name: functionAppName
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
// Outputs - Shown in Azure Portal after deployment
// ---------------------------------------------------------------------------

@description('The API endpoint URL. Use this to call your CodeRunner instance.')
output apiEndpoint string = functionApp.outputs.endpoint

@description('The name of the deployed Function App.')
output functionAppName string = functionApp.outputs.name

@description('The resource group containing all resources.')
output resourceGroup string = resourceGroup().name

@description('Next step: Deploy your code using the Azure Functions Core Tools or VS Code.')
output nextSteps string = 'Run: func azure functionapp publish ${functionApp.outputs.name}'

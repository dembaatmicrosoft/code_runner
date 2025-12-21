// =============================================================================
// Azure Function App Module
// =============================================================================
//
// Deploys a Python 3.11 Function App on Linux with:
//   - Application Insights integration for monitoring
//   - Secure configuration (HTTPS only, TLS 1.2)
//   - Function key authentication
//
// =============================================================================

@description('Name of the Function App.')
param name string

@description('Azure region for the resource.')
param location string

@description('Resource tags.')
param tags object = {}

@description('Resource ID of the App Service Plan.')
param appServicePlanId string

@description('Name of the Storage Account.')
param storageAccountName string

@description('Access key for the Storage Account.')
@secure()
param storageAccountKey string

@description('Application Insights connection string.')
param appInsightsConnectionString string

@description('Application Insights instrumentation key.')
param appInsightsInstrumentationKey string

@description('Name of the content share in Azure Files.')
param contentShareName string

resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: name
  location: location
  tags: union(tags, {
    'azd-service-name': 'api'
  })
  kind: 'functionapp,linux'
  properties: {
    serverFarmId: appServicePlanId
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
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${storageAccountKey};EndpointSuffix=core.windows.net'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};AccountKey=${storageAccountKey};EndpointSuffix=core.windows.net'
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
          value: appInsightsConnectionString
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsightsInstrumentationKey
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

@description('The name of the Function App.')
output name string = functionApp.name

@description('The default hostname of the Function App.')
output hostname string = functionApp.properties.defaultHostName

@description('The endpoint URL of the Function App.')
output endpoint string = 'https://${functionApp.properties.defaultHostName}'

@description('The resource ID of the Function App.')
output id string = functionApp.id

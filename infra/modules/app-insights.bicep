// =============================================================================
// Application Insights Module
// =============================================================================

@description('Name of the Application Insights resource.')
param name string

@description('Azure region for the resource.')
param location string

@description('Resource tags.')
param tags object = {}

@description('Resource ID of the Log Analytics workspace.')
param logAnalyticsWorkspaceId string

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: name
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalyticsWorkspaceId
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

@description('The connection string for Application Insights.')
output connectionString string = appInsights.properties.ConnectionString

@description('The instrumentation key for Application Insights.')
output instrumentationKey string = appInsights.properties.InstrumentationKey

@description('The resource ID of Application Insights.')
output id string = appInsights.id

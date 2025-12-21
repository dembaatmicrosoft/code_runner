// =============================================================================
// Log Analytics Workspace Module
// =============================================================================

@description('Name of the Log Analytics workspace.')
param name string

@description('Azure region for the resource.')
param location string

@description('Resource tags.')
param tags object = {}

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: 1
    }
  }
}

@description('The resource ID of the Log Analytics workspace.')
output id string = logAnalytics.id

@description('The name of the Log Analytics workspace.')
output name string = logAnalytics.name

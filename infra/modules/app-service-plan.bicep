// =============================================================================
// App Service Plan Module
// =============================================================================
//
// Uses the Consumption (Dynamic) tier for Azure Functions:
//   - Pay only for execution time
//   - First 1,000,000 executions/month FREE
//   - First 400,000 GB-s compute/month FREE
//   - Auto-scales based on demand
//
// =============================================================================

@description('Name of the App Service Plan.')
param name string

@description('Azure region for the resource.')
param location string

@description('Resource tags.')
param tags object = {}

@description('SKU configuration for the App Service Plan.')
param sku object = {
  name: 'Y1'
  tier: 'Dynamic'
}

resource appServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: name
  location: location
  tags: tags
  kind: 'functionapp'
  sku: sku
  properties: {
    reserved: true // Required for Linux
  }
}

@description('The resource ID of the App Service Plan.')
output id string = appServicePlan.id

@description('The name of the App Service Plan.')
output name string = appServicePlan.name

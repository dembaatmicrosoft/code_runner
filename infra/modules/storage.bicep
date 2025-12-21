// =============================================================================
// Storage Account Module
// =============================================================================

@description('Name of the Storage Account.')
@minLength(3)
@maxLength(24)
param name string

@description('Azure region for the resource.')
param location string

@description('Resource tags.')
param tags object = {}

@description('Name for the function app content share.')
param contentShareName string

resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: name
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
    // Required for Azure Functions Consumption plan
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// File service for Azure Functions content
resource fileServices 'Microsoft.Storage/storageAccounts/fileServices@2023-01-01' = {
  parent: storage
  name: 'default'
}

// File share for function app content (required for Consumption plan)
resource functionContentShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileServices
  name: contentShareName
  properties: {
    shareQuota: 5120
  }
}

@description('The name of the Storage Account.')
output name string = storage.name

@description('The primary access key for the Storage Account.')
output key string = storage.listKeys().keys[0].value

@description('The resource ID of the Storage Account.')
output id string = storage.id

@description('The primary blob endpoint.')
output blobEndpoint string = storage.properties.primaryEndpoints.blob

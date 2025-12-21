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

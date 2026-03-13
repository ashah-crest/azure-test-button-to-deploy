@description('The name of the function app.')
param functionAppName string

@description('The location into which the resources should be deployed.')
param location string = resourceGroup().location

@description('The zip content URL for released-package.zip.')
var packageUri string = 'https://raw.githubusercontent.com/ashah-crest/azure-test-button-to-deploy/main/released-package.zip'


resource functionAppName_OneDeploy 'Microsoft.Web/sites/extensions@2022-09-01' = {
  name: '${functionAppName}/onedeploy'
  location: location
  properties: {
    packageUri: packageUri
    remoteBuild: false 
  }
}

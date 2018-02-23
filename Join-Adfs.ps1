# SEGES ADFS v2016 farm node installation script
# -

Set-StrictMode -Version Latest
#$VerbosePreference="Continue"
$ErrorActionPreference="Stop"

Import-Module PKI

. .\_Functions.ps1

### Install ADFS v2016 Windows feature
Dism /online /Enable-Feature /FeatureName:IdentityServer-SecurityTokenService /All
#Install-windowsfeature adfs-federation -IncludeManagementTools

$config = Get-Content .\config.json | ConvertFrom-Json

### Import certificates to LocalMachine/My and grant service account read access to private key
Import-CertificateToLocalMachineMyAndGrantAccess $config.SigningCertificate $config.ServiceCredential.Username
Import-CertificateToLocalMachineMyAndGrantAccess $config.DecryptionCertificate $config.ServiceCredential.Username
Import-CertificateToLocalMachineMyAndGrantAccess $config.SslCertificate $config.ServiceCredential.Username

$serviceAccountCredential = Get-AdfsServiceAccountCredential $config

Add-AdfsFarmNode -ServiceAccountCredential $serviceAccountCredential -SQLConnectionString $config.SqlConnectionString -CertificateThumbprint $config.SslCertificate.Thumbprint
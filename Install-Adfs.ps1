# SEGES ADFS v2016 installation script
# Must be run by a domain admin (to initiate schema upgrade) with rights to create databases on the SQL Server (to create config db)

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

# Install-AdfsFarm, like fsconfig before it, cannot properly handle custom signing/encryption certs during farm creation
# https://social.msdn.microsoft.com/Forums/vstudio/en-US/44b888da-0fe9-416a-b7ba-ed879078c2eb/fsconfig-errors?forum=Geneva
# So set those after installation
Install-AdfsFarm    -FederationServiceName $config.ServiceName `
                    -FederationServiceDisplayName $config.ServiceDisplayName `
                    -CertificateThumbprint $config.SslCertificate.Thumbprint  `
                    -ServiceAccountCredential $serviceAccountCredential `
                    -SQLConnectionString $config.SqlConnectionString `
                    -OverwriteConfiguration

Set-AdfsProperties -AutoCertificateRollover $false
Add-AdfsCertificate -CertificateType Token-Signing -Thumbprint $config.SigningCertificate.Thumbprint -IsPrimary
Add-AdfsCertificate -CertificateType Token-Decrypting -Thumbprint $config.DecryptionCertificate.Thumbprint -IsPrimary 

### Customizations
# Enabled IdPInitiatedSignOn
Set-AdfsProperties -EnableIdPInitiatedSignonPage $true
# Authenticate with unqualified samAccountNames via WS-Trust
# See https://technet.microsoft.com/en-us/library/dn636121(v=ws.11).aspx
Set-AdfsClaimsProviderTrust -TargetIdentifier "AD AUTHORITY" -AlternateLoginID samAccountName -LookupForests prod.dli


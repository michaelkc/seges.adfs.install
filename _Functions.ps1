function Grant-ReadPermissionToPrivateKey($certificatePrivateKey, $username)
{
    $rule = new-object security.accesscontrol.filesystemaccessrule $username, "read", allow
    $root = "$env:ALLUSERSPROFILE\microsoft\crypto\rsa\machinekeys"
    $p = [io.path]::combine($root, $certificatePrivateKey)
    Write-Verbose "Private key is at $p"
    $acl = get-acl -path $p
    Write-Verbose "Old ACL"
    $acl.Access|Out-String|Write-Verbose
    $acl.addaccessrule($rule)
    Write-Verbose "New ACL"
    $acl.Access|Out-String|Write-Verbose
    set-acl $p $acl
}

function Import-CertificateToLocalMachineMyAndGrantAccess($certificateConfig, $username)
{
    $certificate = Get-ChildItem Cert:\LocalMachine\My|Where-Object {$_.Thumbprint -eq $certificateConfig.Thumbprint -and $_.HasPrivateKey}
    if ($certificate) 
    {
        Write-Host "Certificate $($certificate.Subject) ($($certificate.Thumbprint)) found in store, skipping import"
    }
    else
    {
        Write-Verbose "Certificate not imported, importing"
        $certificatePfxPassword = $certificateConfig.PfxPassword | ConvertTo-SecureString -AsPlainText -Force
        $certificate = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath $certificateConfig.Pfx -Password $certificatePfxPassword 
        Write-Host "Certificate $($certificate.Subject) ($($certificate.Thumbprint)) imported"
    }
    $certificatePrivateKey = $certificate.privatekey.cspkeycontainerinfo.uniquekeycontainername

    Write-Verbose "Granting $username read access to private key"
    Grant-ReadPermissionToPrivateKey $certificatePrivateKey $username 
}

function Get-AdfsServiceAccountCredential($config)
{
    
    $serviceAccountCredential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList `
                                    $config.ServiceCredential.Username, `
                                    (ConvertTo-SecureString -String $config.ServiceCredential.Password -AsPlainText -Force)
    return $serviceAccountCredential
}
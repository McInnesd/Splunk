function Get-SplunkCertificate {
    [CmdletBinding()]
    param (
        [string[]]$DnsName,
        [Uri]$Url,
        [string]$Template
    )
    
    Write-Host "`n`n`n"
    $SplunkCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $SplunkCertificateChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain

    Write-Host "Attempting to find existing Splunk Certificate"
    try {
        $SplunkCertificateStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Splunk", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        $SplunkCertificateStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    }
    catch {
        Write-Host "Unable to open certificate store Cert:\LocalMachine\Splunk - Error Message: $_"
    }

    try {
        Write-Host "Found $($SplunkCertificateStore.Certificates.Count) SplunkCertificateStore certs"
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Collection = $SplunkCertificateStore.Certificates
        if($Collection.Count -GE 1){
            $CollectionVT = $Collection.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByTimeValid, [System.DateTime]::Now, [bool]::true)
            Write-Host "Found $($CollectionVT.Count) CollectionVT certs"
        }
        if($Collection.Count -GE 1){
            $CollectionSN = $CollectionVT.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindBySubjectName, $ENV:COMPUTERNAME, [bool]::true)
            Write-Host "Found $($CollectionSN.Count) CollectionSN certs"
        }
    }
    catch {
        Write-Host $_
    }

    if($CollectionSN.Count -LT 1){
        try{
            $NewCertificate = Get-Certificate -Template $Template -CertStoreLocation "Cert:\LocalMachine\My" -DnsName $DnsName
            Move-Item -Path "Cert:\\LocalMachine\My\$($NewCertificate.Certificate.Thumbprint)" -Destination "Cert:\\LocalMachine\Splunk"
        }
        catch{
            Write-Host $_
        }
    }
    if($null -NE $NewCertificate.Certificate -or $CollectionSN.Count -EQ 1){
        if($null -NE $NewCertificate.Certificate){
            $SplunkCertificate = $NewCertificate.Certificate
        }
        else{
            $SplunkCertificate = $CollectionSN[0]
        }
        if($SplunkCertificate.HasPrivateKey) {
            [System.Security.Cryptography.RSACng]$SplunkPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($SplunkCertificate)
        }
        if($SplunkPrivateKey.Key.ExportPolicy.HasFlag([System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport)) {
            $SplunkPrivateKeyData = $SplunkPrivateKey.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::GenericPrivateBlob)
            Write-Host "Converting private key to B64"
            $SplunkPrivateKeyString = New-Object System.Text.StringBuilder
            $null = $SplunkPrivateKeyString.AppendLine("-----BEGIN RSA PRIVATE KEY-----")
            $null = $SplunkPrivateKeyString.AppendLine([System.Convert]::ToBase64String($SplunkPrivateKeyData,[System.Base64FormattingOptions]::InsertLineBreaks))
            $null = $SplunkPrivateKeyString.AppendLine("-----END RSA PRIVATE KEY-----")

            Write-host "Writing key to file"
            $SplunkPrivateKeyString.ToString() | Out-File -FilePath "C:\Program Files\Splunk\etc\auth\splunkweb\$($ENV:COMPUTERNAME).key" -Encoding ascii
        }
        $SplunkCertificateStatus = $SplunkCertificateChain.Build($SplunkCertificate)
        if($SplunkCertificateStatus -EQ $True){
            $SplunkCertificateChain.ChainStatus
            $SplunkCertString = New-Object System.Text.StringBuilder
            foreach ($Cert in $SplunkCertificateChain.ChainElements) {
                $null = $SplunkCertString.AppendLine("-----BEGIN CERTIFICATE-----")
                $null = $SplunkCertString.AppendLine([System.Convert]::ToBase64String($Cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert),[System.Base64FormattingOptions]::InsertLineBreaks))
                $null = $SplunkCertString.AppendLine("-----END CERTIFICATE-----")
                   
            }
            Write-host "Writing certificate chain to file"
            $SplunkCertString.ToString() | Out-File -FilePath "C:\Program Files\Splunk\etc\auth\splunkweb\$($ENV:COMPUTERNAME).pem" -Encoding ascii
        }
    }
}



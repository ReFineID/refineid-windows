# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [ValidateSet('All', 'Authentication', 'Qualified')]
    [string]$Role = 'All',

    [ValidateSet('All', 'Pkcs1', 'Pss')]
    [string]$RsaPadding = 'All'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fineIdIssuerPattern = 'Vaestorekisterikeskus|V\u00E4est\u00F6rekisterikeskus|DVV|Digi- ja'
$certificates = @(
    Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.HasPrivateKey -and
            $_.Issuer -match $fineIdIssuerPattern
        }
)
if (-not $certificates) {
    throw 'No FINEID card certificate with a private key was found.'
}

$certificateCases = foreach ($certificate in $certificates) {
    $keyUsage = $certificate.Extensions |
        Where-Object { $_.Oid.Value -eq '2.5.29.15' } |
        Select-Object -First 1
    if (-not ($keyUsage -is [Security.Cryptography.X509Certificates.X509KeyUsageExtension])) {
        continue
    }

    $isQualified = (
        $keyUsage.KeyUsages -band
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation
    ) -ne 0
    $certificateRole = if ($isQualified) { 'Qualified' } else { 'Authentication' }
    if ($Role -ne 'All' -and $Role -ne $certificateRole) {
        continue
    }

    [pscustomobject]@{
        Certificate = $certificate
        Role        = $certificateRole
    }
}
if (-not $certificateCases) {
    throw "No $Role FINEID card certificate with a private key was found."
}

$data = [Text.Encoding]::UTF8.GetBytes('ReFineID sign test payload')

function Test-BytesEqual([byte[]]$Left, [byte[]]$Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) {
        return $false
    }
    [Convert]::ToBase64String($Left) -ceq [Convert]::ToBase64String($Right)
}

function Test-RsaPublicKeyMatch($PrivateKey, $PublicKey) {
    try {
        $privateParameters = $PrivateKey.ExportParameters($false)
        $publicParameters = $PublicKey.ExportParameters($false)
        (Test-BytesEqual $privateParameters.Modulus $publicParameters.Modulus) -and
            (Test-BytesEqual $privateParameters.Exponent $publicParameters.Exponent)
    } catch {
        $false
    }
}

function Test-EcPublicKeyMatch($PrivateKey, $PublicKey) {
    try {
        $privateParameters = $PrivateKey.ExportParameters($false)
        $publicParameters = $PublicKey.ExportParameters($false)
        (Test-BytesEqual $privateParameters.Q.X $publicParameters.Q.X) -and
            (Test-BytesEqual $privateParameters.Q.Y $publicParameters.Q.Y)
    } catch {
        $false
    }
}

$testedKeys = 0
foreach ($case in $certificateCases | Sort-Object @{ Expression = { $_.Role -ne 'Authentication' } }) {
    $certificate = $case.Certificate
    $pinDescription = if ($case.Role -eq 'Authentication') {
        'PIN1 (4-12 digits)'
    } else {
        'PIN2 (6-12 digits)'
    }
    Write-Host "Testing $($case.Role) certificate; Windows will request $pinDescription."

    $rsaPublic = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
    $rsaPrivate = $null
    if ($rsaPublic) {
        try {
            $rsaPrivate = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
        } catch {
            $rsaPrivate = $null
        }
    }
    if ($rsaPublic -and (-not $rsaPrivate -or -not (Test-RsaPublicKeyMatch $rsaPrivate $rsaPublic))) {
        if ($rsaPrivate) {
            $rsaPrivate.Dispose()
        }
        $rsaPublic.Dispose()
        Write-Warning "Skipping a propagated $($case.Role) certificate whose RSA public key does not match the present card container."
        continue
    }
    if ($rsaPrivate -and $rsaPublic) {
        if ($case.Role -eq 'Qualified' -and $RsaPadding -eq 'All') {
            $rsaPrivate.Dispose()
            $rsaPublic.Dispose()
            foreach ($paddingName in @('Pkcs1', 'Pss')) {
                Write-Host "Starting isolated Qualified $paddingName test for one-time PIN2 authentication."
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath `
                    -Role Qualified -RsaPadding $paddingName
                if ($LASTEXITCODE -ne 0) {
                    throw "Qualified $paddingName child test failed with exit code $LASTEXITCODE."
                }
            }
            $testedKeys += 1
            continue
        }

        $paddingCases = if ($RsaPadding -eq 'All') {
            @('Pkcs1', 'Pss')
        } else {
            @($RsaPadding)
        }
        try {
            foreach ($paddingName in $paddingCases) {
                $padding = [Security.Cryptography.RSASignaturePadding]::$paddingName
                $signature = $rsaPrivate.SignData(
                    $data,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    $padding
                )
                $verified = $rsaPublic.VerifyData(
                    $data,
                    $signature,
                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                    $padding
                )
                if (-not $verified) {
                    throw "$paddingName signature verification failed."
                }
                Write-Host "$($case.Role) $paddingName sign and verify passed ($($signature.Length) bytes)."
            }
            $testedKeys += 1
        } finally {
            $rsaPrivate.Dispose()
            $rsaPublic.Dispose()
        }
        continue
    }

    $ecPublic = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate)
    $ecPrivate = $null
    if ($ecPublic) {
        try {
            $ecPrivate = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
        } catch {
            $ecPrivate = $null
        }
    }
    if ($ecPublic -and (-not $ecPrivate -or -not (Test-EcPublicKeyMatch $ecPrivate $ecPublic))) {
        if ($ecPrivate) {
            $ecPrivate.Dispose()
        }
        $ecPublic.Dispose()
        Write-Warning "Skipping a propagated $($case.Role) certificate whose EC public key does not match the present card container."
        continue
    }
    if ($ecPrivate -and $ecPublic) {
        try {
            $signature = $ecPrivate.SignData(
                $data,
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            $verified = $ecPublic.VerifyData(
                $data,
                $signature,
                [Security.Cryptography.HashAlgorithmName]::SHA256
            )
            if (-not $verified) {
                throw 'ECDSA signature verification failed.'
            }
            Write-Host "$($case.Role) ECDSA sign and verify passed ($($signature.Length) bytes)."
            $testedKeys += 1
        } finally {
            $ecPrivate.Dispose()
            $ecPublic.Dispose()
        }
    }
}

if ($testedKeys -eq 0) {
    throw 'FINEID certificates were found, but none exposed a supported RSA or ECDSA private key.'
}

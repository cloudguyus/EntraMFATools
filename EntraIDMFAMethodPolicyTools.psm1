function get-UserToken {
  param (
  )
  $Parameters = @{
    Method     = "GET"
    URI        = "/v1.0/me"
    OutputType = "HttpResponseMessage"
  }
  $Response = Invoke-GraphRequest @Parameters
  $Headers = $Response.RequestMessage.Headers
  $Token = $Headers.Authorization.Parameter
  return $token;
  
}
function Get-CurrentMFAMethods {
  param (
  )
  # Get Graph token from current session
    $token = get-UserToken

    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    $results = @()
    # 1. GA Methods via SDK
    $gaMethods = Get-MgPolicyAuthenticationMethodPolicy | `
                 Select-Object -ExpandProperty AuthenticationMethodConfigurations

    foreach ($method in $gaMethods) {
        $results += [PSCustomObject]@{
            Id    = $method.Id
            State = $method.State
            Type  = "GA"
        }
    }
    # 2. Preview Methods via REST
    $previewEndpoints = @(
        "qrcodepin",
        "hardwareOath"
    )

    foreach ($previewId in $previewEndpoints) {
        try {
            $uri = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$previewId"
            $preview = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET

            $results += [PSCustomObject]@{
                Id    = $preview.id
                State = $preview.state
                Type  = "Preview"
            }
        } catch {
            Write-Warning "Unable to retrieve preview method: $previewId"
        }
    }
    # Output formatted results
    $results | Sort-Object Type | Format-Table -AutoSize
}

function Disable-MFAMethods {
  param (
    [Parameter()] [switch]$SMS,
    [Parameter()] [switch]$Email,
    [Parameter()] [switch]$FIDO2,
    [Parameter()] [switch]$MSFTAuth,
    [Parameter()] [switch]$TAP,
    [Parameter()] [switch]$SoftwareOAUTH,
    [Parameter()] [switch]$Cert,
    [Parameter()] [switch]$Voice,
    [Parameter()] [switch]$QRCode,
    [Parameter()] [switch]$HardwareOAUTH
  )

  if ($Email) {
    Write-Output "Disabling Email OTP..."
    $params = @{
      "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
      id            = "Email"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($FIDO2) {
    Write-Output "Disabling FIDO2..."
    $params = @{
      "@odata.type"         = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
      id                    = "FIDO2"
      state                 = "disabled"
      isAttestationEnforced = $true
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($MSFTAuth) {
    Write-Output "Disabling Microsoft Authenticator..."
    $params = @{
      "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
      id            = "MicrosoftAuthenticator"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($SMS) {
    Write-Output "Disabling SMS..."
    $params = @{
      "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
      id            = "Sms"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($TAP) {
    Write-Output "Disabling Temporary Access Pass (TAP)..."
    $params = @{
      "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
      id            = "TemporaryAccessPass"
      state         = "disabled"
      isUsableOnce  = $true
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($SoftwareOAUTH) {
    Write-Output "Disabling Software OATH..."
    $params = @{
      "@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
      id            = "SoftwareOath"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($Cert) {
    Write-Output "Disabling Certificate-based Authentication..."
    $params = @{
      "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
      id            = "X509Certificate"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($Voice) {
    Write-Output "Disabling Phone (Voice)..."
    $params = @{
      "@odata.type" = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
      id            = "Voice"
      state         = "disabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }
  if ($QRCode) {
    Write-Output "Disabling QR Code..."
    $token = get-UserToken
    # Set headers
    $headers = @{
      "Authorization" = "Bearer $token"
      "Content-Type"  = "application/json"
    }
    # Define request body
    $body = @{
      "@odata.type" = "#microsoft.graph.qrCodePinAuthenticationMethodConfiguration"
      "state"       = "disabled"
    } | ConvertTo-Json -Depth 5
    # Send the PATCH request to Graph beta endpoint
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/qrcodepin" `
      -Method Patch `
      -Headers $headers `
      -Body $body
  }

  if ($HardwareOAUTH) {
    Write-Output "Disabling Hardware OAuth..."
    $token = get-UserToken
    # Set headers
    $headers = @{
      "Authorization" = "Bearer $token"
      "Content-Type"  = "application/json"
    }
    # Define request body
    $body = @{
      "@odata.type"= "#microsoft.graph.hardwareOathAuthenticationMethodConfiguration"
      "state"= "disabled"
    } | ConvertTo-Json -Depth 5
    # Send the PATCH request to Graph beta endpoint
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/hardwareOath" `
      -Method Patch `
      -Headers $headers `
      -Body $body
  }
}
function Enable-MFAMethods {
  param (
    [Parameter()] [switch]$SMS,
    [Parameter()] [switch]$Email,
    [Parameter()] [switch]$FIDO2,
    [Parameter()] [switch]$MSFTAuth,
    [Parameter()] [switch]$TAP,
    [Parameter()] [switch]$SoftwareOAUTH,
    [Parameter()] [switch]$Cert,
    [Parameter()] [switch]$Voice,
    [Parameter()] [switch]$QRCode,
    [Parameter()] [switch]$HardwareOAUTH
  )

  if ($Email) {
    Write-Output "Enabling Email OTP..."
    $params = @{
      "@odata.type" = "#microsoft.graph.emailAuthenticationMethodConfiguration"
      id            = "Email"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($FIDO2) {
    Write-Output "Enabling FIDO2..."
    $params = @{
      "@odata.type"         = "#microsoft.graph.fido2AuthenticationMethodConfiguration"
      id                    = "FIDO2"
      state                 = "enabled"
      isAttestationEnforced = $true
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($MSFTAuth) {
    Write-Output "Enabling Microsoft Authenticator..."
    $params = @{
      "@odata.type" = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration"
      id            = "MicrosoftAuthenticator"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($SMS) {
    Write-Output "Enabling SMS..."
    $params = @{
      "@odata.type" = "#microsoft.graph.smsAuthenticationMethodConfiguration"
      id            = "Sms"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($TAP) {
    Write-Output "Enabling Temporary Access Pass (TAP)..."
    $params = @{
      "@odata.type" = "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration"
      id            = "TemporaryAccessPass"
      state         = "enabled"
      isUsableOnce  = $true
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($SoftwareOAUTH) {
    Write-Output "Enabling Software OATH..."
    $params = @{
      "@odata.type" = "#microsoft.graph.softwareOathAuthenticationMethodConfiguration"
      id            = "SoftwareOath"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($Cert) {
    Write-Output "Enabling Certificate-based Authentication..."
    $params = @{
      "@odata.type" = "#microsoft.graph.x509CertificateAuthenticationMethodConfiguration"
      id            = "X509Certificate"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($Voice) {
    Write-Output "Enabling Phone (Voice)..."
    $params = @{
      "@odata.type" = "#microsoft.graph.voiceAuthenticationMethodConfiguration"
      id            = "Voice"
      state         = "enabled"
    }
    Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
      -AuthenticationMethodConfigurationId $params.id `
      -BodyParameter $params
  }

  if ($QRCode) {
    Write-Output "Enabling QR Code..."
    $token = get-UserToken
    $headers = @{
      "Authorization" = "Bearer $token"
      "Content-Type"  = "application/json"
    }
    $body = @{
      "@odata.type" = "#microsoft.graph.qrCodePinAuthenticationMethodConfiguration"
      "state"       = "enabled"
      "standardQRCodeLifetimeInDays" = 365
      "pinLength" = 8
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/qrcodepin" `
      -Method Patch `
      -Headers $headers `
      -Body $body
  }

  if ($HardwareOAUTH) {
    Write-Output "Enabling Hardware OAuth..."
    $token = get-UserToken
    $headers = @{
      "Authorization" = "Bearer $token"
      "Content-Type"  = "application/json"
    }
    $body = @{
      "@odata.type"= "#microsoft.graph.hardwareOathAuthenticationMethodConfiguration"
      "state"= "enabled"
    } | ConvertTo-Json -Depth 5
    Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/hardwareOath" `
      -Method Patch `
      -Headers $headers `
      -Body $body
  }
}
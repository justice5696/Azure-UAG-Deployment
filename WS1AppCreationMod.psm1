#Sources: 
    # Code Sample - Ws1A with powershell: https://developer.vmware.com/samples/6217/code1458-api-samples#
    #Getting started with WS1 api: https://techzone.vmware.com/blog/lets-git-committed-resources-getting-started-workspace-one-access-apis


Param (
        [parameter(Position=0,Mandatory=$true)][string]$idmserver, 
        [parameter(Position=1,Mandatory=$true)][string]$IDMclientID, 
        [parameter(Position=2,Mandatory=$true)][string]$IDMSharedSecret, 
        [parameter(Position=3,Mandatory=$true)][string]$uagName, 
        [parameter(Position=4,Mandatory=$true)][string]$uagIP,
        [parameter(Position=5,Mandatory=$true)][string]$AccessPolicy,
        [parameter(Position=6,Mandatory=$true)][string[]]$GroupList
    )

$script:policyUUID
$script:appUUID

function LogintoIDM {
    Param ($idmserver, $IDMclientID, $IDMSharedSecret)

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Could switch back to this to prompt for Shared Secret each time
    #$IDMSharedSecret = Read-Host -Prompt 'Enter the Shared Secret'

    #Base64 encode the client name and shared secret
    $pair = "${IDMclientID}:${IDMSharedSecret}"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $basicAuthValue = "Basic $base64"

    #Retrieve oAuth2 Token
    Write-Host "Getting Token From: $idmserver"
    $headers = @{Authorization = $basicAuthValue }
    try {
        $sresult = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/API/1.0/oauth2/token?grant_type=client_credentials" -Headers $headers 
    }
    catch {

        Write-Host "An error occurred when logging on to IDM $_"
        break 
    }

    #Save the returned oAuth2 token to Variable
    $IDMToken = $sresult.access_token

    Write-Host "Successfully Logged In"
    Write-Host "IDMToken is $($IDMToken)"

    return $IDMToken

     
}

# get all access policies and return the ID of the Policy with the same name as TargetPolicy
function GetAccessPolicy{
    Param ($IDMtoken, $idmserver, $TargetPolicy)

    #Check if the user is logged in
    if ([string]::IsNullOrEmpty($IDMToken))
    {
      write-host "You are not logged into IDM"
      break   
    }

    Write-Host "Getting Workspace ONE Access Policies on: $idmserver"
    Write-Host "................................................................."

    #Create header with oAuth2 Token
    $bearerAuthValue = "Bearer $IDMToken"
    $headers = @{ Authorization = $bearerAuthValue }  

    try{
        $AccessPoliciesRaw = Invoke-WebRequest -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/accessPolicies" -Headers $headers -ContentType "application/json"
    }
    catch {
        Write-Host "An error occurred when getting the Access Policies $_"
        break 
    }

    #HAD TO PARSE like this because I could not figure out how to parse the data returned by Invoke-RestMethod.
        # This should always work because WS1 requires that there is at least one access policy at all times - the Default_Access_Policy_Set
    $RawString = $AccessPoliciesRaw.RawContent
    $FIRST = $RawString.IndexOf('[{"name')
    $RawString = $RawString.substring($FIRST)
    $LAST = $RawString.LastIndexOf('}]')
    $RawString = $RawString.substring(0,$LAST+2)
    $obby = $RawString | ConvertFrom-Json
    #$obby | Format-Table
    Write-Host "................................................................."
    foreach ($ob in $obby){
        Write-Host "Name: is $($ob.name) | UUID: is $($ob.uuid)"
        if($ob.name -eq $TargetPolicy){
            Write-Host "Found the Target Policy: $($ob.Name) - returning the UUID"
            $script:policyUUID = "$($ob.uuid)"
        }
    }
}

## Construct the App JSON and send Post to create web app
function CreateWebApp{
    
    param($policyUUID, $uagName, $uagIP, $IDMToken, $idmserver)

    Write-Host "Crafting Web App Creation JSON"
    $bearerAuthValue = "Bearer $IDMToken"
    $headers = @{ Authorization = $bearerAuthValue }  


    $appName = "$($uagName)-$($uagIP)"
    $uuid = New-Guid
    $uuid = $uuid.ToString()
    $recipientName = "https://$($uagIP):9443/login/saml2/sso/admin"
    $audience = "https://$($uagIP):9443/admin"
    $assertionConsumerServiceUrl = "https://$($uagIP):9443/login/saml2/sso/admin"

    # had a lot of trouble getting the right format for the JSON String. This type works. The other two may work as well - keeping them for reference
    #BEGIN/END Cert and \n only - WORKING!!!!!!!!!!!!!
    $appJSON="{`"uuid`":`"$uuid`",`"name`":`"$appName`",`"catalogItemType`":`"Saml20`",`"internal`":false,`"labels`":[],`"description`":`"SAMLWebapptoallowfortheUAGAdminportaltologinviaSAML`",`"accessPolicySetUuid`":`"$policyUUID`",`"visible`":false,`"packageVersion`":`"1.0`",`"provisioningAdapter`":null,`"provisioningAdapterId`":null,`"isProvisioningEnabled`":false,`"resourceConfiguration`":{`"applicationAttributeMap`":null,`"parameterValues`":{}},`"authInfo`":{`"nameIdFormat`":`"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`",`"nameIdFormatVal`":null,`"nameIdClaimTransformation`":null,`"nameId`":`"`$`{user.userName`}`",`"recipientName`":`"$recipientName`",`"audience`":`"$audience`",`"assertionConsumerServiceUrl`":`"$assertionConsumerServiceUrl`",`"signingCert`":`"-----BEGIN CERTIFICATE-----\nMIIGyzCCBbOgAwIBAgIQFsQTeZ1dr7H8WIZGQ1Y+mDANBgkqhkiG9w0BAQsFADCB\nujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT\nH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy\nMDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG\nA1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0y\nMjAzMDcxNzA3MTVaFw0yMzAzMDcxNzA3MTVaMGwxCzAJBgNVBAYTAlVTMQ4wDAYD\nVQQIEwVUZXhhczETMBEGA1UEBxMKRm9ydCBXb3J0aDEeMBwGA1UEChMVQW1lcmlj\nYW4gQWlybGluZXMgSW5jMRgwFgYDVQQDEw91YWd6ZXVzbi5hYS5jb20wggEiMA0G\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDuYADGciw0k7imT/L5OYAG6nhlbDou\nlL/jLNKQHbdiQqap/st48Qc2fGyr5yk2hhK0dAvZ2AocZb6M+Q4m4rQfdW8BN8ns\nuDYTy6xVjjy2AMSrR1Hb6c6zzs0rE2VOZpUiZEHDXzpAuMjqcksoqIJCNq3WdBcW\n/mdd1KoZzd91Q0KLrsrMGqfirJ4949F/usn6SlNLcFujHBX27BP1iosCJs+kbNOx\nxn9ARfSOOnURXDuu3A1qPfZouQMvfVovCtYikZUAHo+zShdonu00+rc/bvfxjGgz\nWSylKcURQlvx6Ff/nkFFAOtD0n2ACEVwkbYLMK+TvAAXUsnMGN9MqlZ1AgMBAAGj\nggMYMIIDFDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQgDDgsuOC1oC8WJUDIXHye\na+tqdDAfBgNVHSMEGDAWgBSConB03bxTP8971PfNf6dgxgpMvzBoBggrBgEFBQcB\nAQRcMFowIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDMGCCsG\nAQUFBzAChidodHRwOi8vYWlhLmVudHJ1c3QubmV0L2wxay1jaGFpbjI1Ni5jZXIw\nMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbnRydXN0Lm5ldC9sZXZlbDFr\nLmNybDAnBgNVHREEIDAegg91YWd6ZXVzbi5hYS5jb22CC3ZkaW4uYWEuY29tMA4G\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwTAYD\nVR0gBEUwQzA3BgpghkgBhvpsCgEFMCkwJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3\nLmVudHJ1c3QubmV0L3JwYTAIBgZngQwBAgIwggF9BgorBgEEAdZ5AgQCBIIBbQSC\nAWkBZwB1AFWB1MIWkDYBSuoLm1c8U/DA5Dh4cCUIFy+jqh0HE9MMAAABf2VZd1kA\nAAQDAEYwRAIgZi7YYYbEXI5jNcSaKPEFLj7xkLOi2VLXFZsc5njf7CgCICQegOst\n/w9EMZP4/xvzaBvJ9eEdPZkr+Y9akelrxoV5AHYAtz77JN+cTbp18jnFulj0bF38\nQs96nzXEnh0JgSXttJkAAAF/ZVl3PwAABAMARzBFAiEA85QkCzBhvUxRc+qxwoJn\n7hjps2n7ZM/zXAWh8RloHiUCIFIMW/b5HLkRwmo252w0lnpMXjdU6fKfGatsZ7Au\ngFETAHYA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAF/ZVl3agAA\nBAMARzBFAiEAstYxpGXmXleY6eiTz1kwqqo2dEN9EeexG8jfmuggyW8CICk5FEgZ\nBjkIMG8tO4toBFtGyoAiMDW47Hj19CwbiB60MA0GCSqGSIb3DQEBCwUAA4IBAQDF\nUMpPw0ZEPjFofSDz+kAywzlnAMSwlaet/iArt/nJ8I7C8J3evTlSFk8F/NmjFddJ\nNLVPZXlE2dNyvLHl20syFi2qj/ZwVniy9gjYaKUUZMzYq/VWIqicW61EGRsGhe3c\ny0+P2KFF87vPHt8MWSAq/hqlXMydU+zV4BgoJhn+3YuZAxftqQuldhOX8OqwXiUY\nxJdyy5n5Jyr/P20vzz4rtnOMYT1q4A38GYwyvo3H5BcpRTSnVs7f68qw+mG1q3yf\nOws0YWOrw2lmMK/g97SDYCXT6X8ghG9rH2hgR69SBD4wpHqVPiFps2F/pVHahafE\nIc6r+7LHmRMJgDzR4HI2\n-----END CERTIFICATE-----`",`"validityTimeSeconds`":200,`"parameters`":[],`"attributes`":[],`"signatureAlgorithm`":`"SHA1withRSA`",`"digestAlgorithm`":`"SHA1`",`"claimTransformations`":[],`"type`":`"Saml20`",`"configureAs`":`"manual`",`"includeDestination`":true,`"signAssertion`":false,`"signResponse`":true,`"encryptAssertion`":false,`"includeSigningCert`":false,`"returnFailureResponse`":false,`"loginRedirectionUrl`":null,`"relayState`":null,`"encryptionCerts`":null,`"allowApiAccess`":false,`"credentialCheckType`":`"PerAppPassword`",`"proxyCount`":null,`"metadata`":null,`"metadataUrl`":null,`"deviceSsoResponse`":false,`"enableForceAuthnRequest`":false}}" 
        #no begin/end cert and \r\n
        #$appJSON="{`"uuid`":`"$uuid`",`"name`":`"$appName`",`"catalogItemType`":`"Saml20`",`"internal`":false,`"labels`":[],`"description`":`"SAMLWebapptoallowfortheUAGAdminportaltologinviaSAML`",`"accessPolicySetUuid`":`"$policyUUID`",`"visible`":false,`"packageVersion`":`"1.0`",`"provisioningAdapter`":null,`"provisioningAdapterId`":null,`"isProvisioningEnabled`":false,`"resourceConfiguration`":{`"applicationAttributeMap`":null,`"parameterValues`":{}},`"authInfo`":{`"nameIdFormat`":`"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`",`"nameIdFormatVal`":null,`"nameIdClaimTransformation`":null,`"nameId`":`"`$`{user.userName`}`",`"recipientName`":`"$recipientName`",`"audience`":`"$audience`",`"assertionConsumerServiceUrl`":`"$assertionConsumerServiceUrl`",`"signingCert`":`"MIIGyzCCBbOgAwIBAgIQFsQTeZ1dr7H8WIZGQ1Y+mDANBgkqhkiG9w0BAQsFADCB\r\nujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT\r\nH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy\r\nMDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG\r\nA1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0y\r\nMjAzMDcxNzA3MTVaFw0yMzAzMDcxNzA3MTVaMGwxCzAJBgNVBAYTAlVTMQ4wDAYD\r\nVQQIEwVUZXhhczETMBEGA1UEBxMKRm9ydCBXb3J0aDEeMBwGA1UEChMVQW1lcmlj\r\nYW4gQWlybGluZXMgSW5jMRgwFgYDVQQDEw91YWd6ZXVzbi5hYS5jb20wggEiMA0G\r\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDuYADGciw0k7imT/L5OYAG6nhlbDou\r\nlL/jLNKQHbdiQqap/st48Qc2fGyr5yk2hhK0dAvZ2AocZb6M+Q4m4rQfdW8BN8ns\r\nuDYTy6xVjjy2AMSrR1Hb6c6zzs0rE2VOZpUiZEHDXzpAuMjqcksoqIJCNq3WdBcW\r\n/mdd1KoZzd91Q0KLrsrMGqfirJ4949F/usn6SlNLcFujHBX27BP1iosCJs+kbNOx\r\nxn9ARfSOOnURXDuu3A1qPfZouQMvfVovCtYikZUAHo+zShdonu00+rc/bvfxjGgz\r\nWSylKcURQlvx6Ff/nkFFAOtD0n2ACEVwkbYLMK+TvAAXUsnMGN9MqlZ1AgMBAAGj\r\nggMYMIIDFDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQgDDgsuOC1oC8WJUDIXHye\r\na+tqdDAfBgNVHSMEGDAWgBSConB03bxTP8971PfNf6dgxgpMvzBoBggrBgEFBQcB\r\nAQRcMFowIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDMGCCsG\r\nAQUFBzAChidodHRwOi8vYWlhLmVudHJ1c3QubmV0L2wxay1jaGFpbjI1Ni5jZXIw\r\nMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbnRydXN0Lm5ldC9sZXZlbDFr\r\nLmNybDAnBgNVHREEIDAegg91YWd6ZXVzbi5hYS5jb22CC3ZkaW4uYWEuY29tMA4G\r\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwTAYD\r\nVR0gBEUwQzA3BgpghkgBhvpsCgEFMCkwJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3\r\nLmVudHJ1c3QubmV0L3JwYTAIBgZngQwBAgIwggF9BgorBgEEAdZ5AgQCBIIBbQSC\r\nAWkBZwB1AFWB1MIWkDYBSuoLm1c8U/DA5Dh4cCUIFy+jqh0HE9MMAAABf2VZd1kA\r\nAAQDAEYwRAIgZi7YYYbEXI5jNcSaKPEFLj7xkLOi2VLXFZsc5njf7CgCICQegOst\r\n/w9EMZP4/xvzaBvJ9eEdPZkr+Y9akelrxoV5AHYAtz77JN+cTbp18jnFulj0bF38\r\nQs96nzXEnh0JgSXttJkAAAF/ZVl3PwAABAMARzBFAiEA85QkCzBhvUxRc+qxwoJn\r\n7hjps2n7ZM/zXAWh8RloHiUCIFIMW/b5HLkRwmo252w0lnpMXjdU6fKfGatsZ7Au\r\ngFETAHYA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAF/ZVl3agAA\r\nBAMARzBFAiEAstYxpGXmXleY6eiTz1kwqqo2dEN9EeexG8jfmuggyW8CICk5FEgZ\r\nBjkIMG8tO4toBFtGyoAiMDW47Hj19CwbiB60MA0GCSqGSIb3DQEBCwUAA4IBAQDF\r\nUMpPw0ZEPjFofSDz+kAywzlnAMSwlaet/iArt/nJ8I7C8J3evTlSFk8F/NmjFddJ\r\nNLVPZXlE2dNyvLHl20syFi2qj/ZwVniy9gjYaKUUZMzYq/VWIqicW61EGRsGhe3c\r\ny0+P2KFF87vPHt8MWSAq/hqlXMydU+zV4BgoJhn+3YuZAxftqQuldhOX8OqwXiUY\r\nxJdyy5n5Jyr/P20vzz4rtnOMYT1q4A38GYwyvo3H5BcpRTSnVs7f68qw+mG1q3yf\r\nOws0YWOrw2lmMK/g97SDYCXT6X8ghG9rH2hgR69SBD4wpHqVPiFps2F/pVHahafE\r\nIc6r+7LHmRMJgDzR4HI2`",`"validityTimeSeconds`":200,`"parameters`":[],`"attributes`":[],`"signatureAlgorithm`":`"SHA1withRSA`",`"digestAlgorithm`":`"SHA1`",`"claimTransformations`":[],`"type`":`"Saml20`",`"configureAs`":`"manual`",`"includeDestination`":true,`"signAssertion`":false,`"signResponse`":true,`"encryptAssertion`":false,`"includeSigningCert`":false,`"returnFailureResponse`":false,`"loginRedirectionUrl`":null,`"relayState`":null,`"encryptionCerts`":null,`"allowApiAccess`":false,`"credentialCheckType`":`"PerAppPassword`",`"proxyCount`":null,`"metadata`":null,`"metadataUrl`":null,`"deviceSsoResponse`":false,`"enableForceAuthnRequest`":false}}"
        # begin/end cert and \r\n
        #$appJSON="{`"uuid`":`"$uuid`",`"name`":`"$appName`",`"catalogItemType`":`"Saml20`",`"internal`":false,`"labels`":[],`"description`":`"SAMLWebapptoallowfortheUAGAdminportaltologinviaSAML`",`"accessPolicySetUuid`":`"$policyUUID`",`"visible`":false,`"packageVersion`":`"1.0`",`"provisioningAdapter`":null,`"provisioningAdapterId`":null,`"isProvisioningEnabled`":false,`"resourceConfiguration`":{`"applicationAttributeMap`":null,`"parameterValues`":{}},`"authInfo`":{`"nameIdFormat`":`"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`",`"nameIdFormatVal`":null,`"nameIdClaimTransformation`":null,`"nameId`":`"`$`{user.userName`}`",`"recipientName`":`"$recipientName`",`"audience`":`"$audience`",`"assertionConsumerServiceUrl`":`"$assertionConsumerServiceUrl`",`"signingCert`":`"-----BEGIN CERTIFICATE-----\r\nMIIGyzCCBbOgAwIBAgIQFsQTeZ1dr7H8WIZGQ1Y+mDANBgkqhkiG9w0BAQsFADCB\r\nujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT\r\nH1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy\r\nMDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG\r\nA1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0y\r\nMjAzMDcxNzA3MTVaFw0yMzAzMDcxNzA3MTVaMGwxCzAJBgNVBAYTAlVTMQ4wDAYD\r\nVQQIEwVUZXhhczETMBEGA1UEBxMKRm9ydCBXb3J0aDEeMBwGA1UEChMVQW1lcmlj\r\nYW4gQWlybGluZXMgSW5jMRgwFgYDVQQDEw91YWd6ZXVzbi5hYS5jb20wggEiMA0G\r\nCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDuYADGciw0k7imT/L5OYAG6nhlbDou\r\nlL/jLNKQHbdiQqap/st48Qc2fGyr5yk2hhK0dAvZ2AocZb6M+Q4m4rQfdW8BN8ns\r\nuDYTy6xVjjy2AMSrR1Hb6c6zzs0rE2VOZpUiZEHDXzpAuMjqcksoqIJCNq3WdBcW\r\n/mdd1KoZzd91Q0KLrsrMGqfirJ4949F/usn6SlNLcFujHBX27BP1iosCJs+kbNOx\r\nxn9ARfSOOnURXDuu3A1qPfZouQMvfVovCtYikZUAHo+zShdonu00+rc/bvfxjGgz\r\nWSylKcURQlvx6Ff/nkFFAOtD0n2ACEVwkbYLMK+TvAAXUsnMGN9MqlZ1AgMBAAGj\r\nggMYMIIDFDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQgDDgsuOC1oC8WJUDIXHye\r\na+tqdDAfBgNVHSMEGDAWgBSConB03bxTP8971PfNf6dgxgpMvzBoBggrBgEFBQcB\r\nAQRcMFowIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDMGCCsG\r\nAQUFBzAChidodHRwOi8vYWlhLmVudHJ1c3QubmV0L2wxay1jaGFpbjI1Ni5jZXIw\r\nMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbnRydXN0Lm5ldC9sZXZlbDFr\r\nLmNybDAnBgNVHREEIDAegg91YWd6ZXVzbi5hYS5jb22CC3ZkaW4uYWEuY29tMA4G\r\nA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwTAYD\r\nVR0gBEUwQzA3BgpghkgBhvpsCgEFMCkwJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3\r\nLmVudHJ1c3QubmV0L3JwYTAIBgZngQwBAgIwggF9BgorBgEEAdZ5AgQCBIIBbQSC\r\nAWkBZwB1AFWB1MIWkDYBSuoLm1c8U/DA5Dh4cCUIFy+jqh0HE9MMAAABf2VZd1kA\r\nAAQDAEYwRAIgZi7YYYbEXI5jNcSaKPEFLj7xkLOi2VLXFZsc5njf7CgCICQegOst\r\n/w9EMZP4/xvzaBvJ9eEdPZkr+Y9akelrxoV5AHYAtz77JN+cTbp18jnFulj0bF38\r\nQs96nzXEnh0JgSXttJkAAAF/ZVl3PwAABAMARzBFAiEA85QkCzBhvUxRc+qxwoJn\r\n7hjps2n7ZM/zXAWh8RloHiUCIFIMW/b5HLkRwmo252w0lnpMXjdU6fKfGatsZ7Au\r\ngFETAHYA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAF/ZVl3agAA\r\nBAMARzBFAiEAstYxpGXmXleY6eiTz1kwqqo2dEN9EeexG8jfmuggyW8CICk5FEgZ\r\nBjkIMG8tO4toBFtGyoAiMDW47Hj19CwbiB60MA0GCSqGSIb3DQEBCwUAA4IBAQDF\r\nUMpPw0ZEPjFofSDz+kAywzlnAMSwlaet/iArt/nJ8I7C8J3evTlSFk8F/NmjFddJ\r\nNLVPZXlE2dNyvLHl20syFi2qj/ZwVniy9gjYaKUUZMzYq/VWIqicW61EGRsGhe3c\r\ny0+P2KFF87vPHt8MWSAq/hqlXMydU+zV4BgoJhn+3YuZAxftqQuldhOX8OqwXiUY\r\nxJdyy5n5Jyr/P20vzz4rtnOMYT1q4A38GYwyvo3H5BcpRTSnVs7f68qw+mG1q3yf\r\nOws0YWOrw2lmMK/g97SDYCXT6X8ghG9rH2hgR69SBD4wpHqVPiFps2F/pVHahafE\r\nIc6r+7LHmRMJgDzR4HI2\r\n-----END CERTIFICATE-----`",`"validityTimeSeconds`":200,`"parameters`":[],`"attributes`":[],`"signatureAlgorithm`":`"SHA1withRSA`",`"digestAlgorithm`":`"SHA1`",`"claimTransformations`":[],`"type`":`"Saml20`",`"configureAs`":`"manual`",`"includeDestination`":true,`"signAssertion`":false,`"signResponse`":true,`"encryptAssertion`":false,`"includeSigningCert`":false,`"returnFailureResponse`":false,`"loginRedirectionUrl`":null,`"relayState`":null,`"encryptionCerts`":null,`"allowApiAccess`":false,`"credentialCheckType`":`"PerAppPassword`",`"proxyCount`":null,`"metadata`":null,`"metadataUrl`":null,`"deviceSsoResponse`":false,`"enableForceAuthnRequest`":false}}"
    

    Write-Host "................................................................."
    


    try{
        #keeping both of these. The return of Invoke-WebRequest is easier to work with but Invoke-ResstMethod is more streamlined.
        $appCreate = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/catalogitems" -Headers $headers -Body $appJSON -ContentType "application/vnd.vmware.horizon.manager.catalog.saml20+json"
        #$appCreate = Invoke-WebRequest -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/catalogitems" -Headers $headers -Body $appJSON -ContentType "application/vnd.vmware.horizon.manager.catalog.saml20+json"
    }
    catch {
        Write-Host "An error occurred when creating the app $_"
        break
    }
    

    Write-Host "................................................................."
    
    $RawString = $appCreate.uuid
    Write-Host "App UUID is: $RawString"

    #no return, just writing to a Script scope variable because I had trouble with the formatting of returning.
    $script:appUUID = $RawString
    
}
#Take in a list of WS1 Groups. Iterate through each one and do a query to get the Group UUID for that group.
function GetGroupIDs{
    param($IDMtoken, $idmserver, $grouplist)
    Write-Host "................................................................."
    Write-Host "................................................................."
    
    $IDList = @()

    #Check if the user is logged in
    if ([string]::IsNullOrEmpty($IDMToken))
    {
      write-host "You are not logged into IDM"
      break   
    }

    Write-Host "Getting Workspace ONE Access Group IDs: $idmserver"
  

    #Create header with oAuth2 Token
    $bearerAuthValue = "Bearer $IDMToken"
    $headers = @{ Authorization = $bearerAuthValue }  

    # Iterate through each group in the passed in group list.
    foreach($group in $grouplist){
        Write-Host "Iterating through each Group in the passed in GroupList"
        try{
            $GroupIDs = Invoke-RestMethod -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Groups?filter=displayName%20eq%20%22$($group)%22" -Headers $headers -ContentType "application/json"
            #$GroupIDs = Invoke-WebRequest -Method Get -Uri "https://$idmserver/SAAS/jersey/manager/api/scim/Groups?filter=displayName%20eq%20%22$($group)%22" -Headers $headers -ContentType "application/json"
        }
        catch {
            Write-Host "An error occurred when getting the Access Groups $_"
            Write-Host "Skipping this group, but will continue with the next group in the provided Group list"
            #break 
            Continue
        }

        $TotalResults = $GroupIDs.totalResults

        if($TotalResults -eq 1){
            Write-Host "Total number of results for the single group query for DisplayName='$($group) is 1 (TotalResults=$($TotalResults)) - proceeding with getting the Group's ID"
            $IDString = $GroupIDs.Resources.id
            $GroupName =  $GroupIDs.Resources.displayName
            Write-Host "GroupName=$($GroupName) & GroupID=$($IDString)"
            $IDList += $IDString
        }
        else{
            Write-Host "Received TotalResults=$($TotalResults) when searching for DisplayName='$($group)' - this needs to be 1 to proceed"
        }
    }

    return $IDList
}


#Take in a list of Group UUIDs and a web App UUID and create an entitlement to the App
function AssignWebApp{
   
    param($IDMtoken, $idmserver, $groupIDs)
    Write-Host "................................................................."

    Write-Host "Creating a WS1 Web App Entitlement. Confirming you are still logged in and have a valid App UUID."

    #Check if the user is logged in
    if ([string]::IsNullOrEmpty($IDMToken))
    {
      write-host "You are not logged into IDM"
      break   
    }

    if ([string]::IsNullOrEmpty($script:appUUID))
    {
      write-host "The App UUID has not been found"
      break   
    }
    $appID = $script:appUUID

    Write-Host "Creating Workspace ONE Access Entitlement for app=$($appID) and groups=$($groupIDs)"

    #Create header with oAuth2 Token
    $bearerAuthValue = "Bearer $IDMToken"
    $headers = @{ Authorization = $bearerAuthValue }  

    #Construct the ENTITLEMENT JSON string which depends on the number of 
    $entitlementJSON="{`"returnPayloadOnError`":true,`"operations`":["
    for($i=0; $i -lt $groupIDs.Count; $i++){
        if($i -ne 0){
            $entitlementJSON+=","
        }
        $groupID=$groupIDs[$i]
        $indivJSON = "{`"method`":`"POST`",`"data`":{`"catalogItemId`":`"$appID`",`"subjectType`":`"GROUPS`",`"subjectId`":`"$groupID`",`"activationPolicy`":`"AUTOMATIC`"}}"
        $entitlementJSON+=$indivJSON

        if($i -eq ($groupIDs.Count-1)){
            $entitlementJSON+="],`"_links`":{}}"
        }
    }

    Write-Host "EntitlementJSON to send in API POST is : $($entitlementJSON)"
    
    #Test using a single group
    #$groupID = $groupIDs[0]
    #$entitlementJSON="{`"returnPayloadOnError`":true,`"operations`":[{`"method`":`"POST`",`"data`":{`"catalogItemId`":`"$appID`",`"subjectType`":`"GROUPS`",`"subjectId`":`"$groupID`",`"activationPolicy`":`"AUTOMATIC`"}}],`"_links`":{}}"

    try{
        #$entitlementCreate = Invoke-RestMethod -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/entitlements/definitions" -Headers $headers -Body $entitlementJSON -ContentType "application/vnd.vmware.horizon.manager.entitlements.definition.bulk+json"
        $entitlementCreate = Invoke-WebRequest -Method Post -Uri "https://$idmserver/SAAS/jersey/manager/api/entitlements/definitions" -Headers $headers -Body $entitlementJSON -ContentType "application/vnd.vmware.horizon.manager.entitlements.definition.bulk+json"
    }
    catch {
        Write-Host "An error occurred when creating the app $_"
        break
    }

    Write-Host "................................................................."
    Write-Host "................................................................."

    $RawString = $entitlementCreate.RawContent
    Write-Host "Entitlement Creation Response is: $RawString"

}


######################################################################################################################################################################
###################################################################     MAIN      ####################################################################################
######################################################################################################################################################################

Write-Host "Logging into Workspace One Access" -foregroundcolor Blue -backgroundcolor Black
$token = LogintoIDM -idmserver $idmserver -IDMclientID $IDMclientID -IDMSharedSecret $IDMSharedSecret
Write-Host "................................................................."
Write-Host "................................................................."

Write-Host "Getting UUID of supplied WS1 Access Policy" -foregroundcolor Blue -backgroundcolor Black
GetAccessPolicy -IDMToken $token -idmserver $idmserver -TargetPolicy $AccessPolicy
if($script:policyUUID.Length -eq 0){
    Write-Host "Error getting Access Policy UUID. Ending Script." -foregroundcolor Red -backgroundcolor Black
    exit
}
Write-Host "Policy UUID = $($script:policyUUID)" -foregroundcolor Blue -backgroundcolor Black
Write-Host "................................................................."
Write-Host "................................................................."


Write-Host "Creating the WS1 SAML Web App for the UAG" -foregroundcolor Blue -backgroundcolor Black
CreateWebApp -policyUUID $script:policyUUID -uagName $uagName -uagIP $uagIP -IDMToken $token -idmserver $idmserver
if($script:appUUID.Length -eq 0){
    Write-Host "Error getting App UUID. Ending Script." -foregroundcolor Red -backgroundcolor Black
    exit
}
Write-Host "App UUID = $($script:appUUID)" -foregroundcolor Blue -backgroundcolor Black
Write-Host "................................................................."
Write-Host "................................................................."


Write-Host "Getting the UUIDs of the given WS1 Groups" -foregroundcolor Blue -backgroundcolor Black
$AllGroupIDs = GetGroupIDs -IDMToken $token -idmserver $idmserver -grouplist $GroupList
Write-Host "Printing returned GroupIDs"
Foreach($id in $AllGroupIDs){Write-Host "Group ID: $id"}
Write-Host "................................................................."
Write-Host "................................................................."


Write-Host "Assigning the created Web App to the supplied WS1 Groups" -foregroundcolor Blue -backgroundcolor Black
AssignWebApp -IDMtoken $token -idmserver $idmserver -groupIDs $AllGroupIDs
Write-Host "................................................................."
Write-Host "................................................................."

Write-Host "WS1 APP CREATION SCRIPT COMPLETED" -foregroundcolor Blue -backgroundcolor Black
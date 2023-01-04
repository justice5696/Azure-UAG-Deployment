#
#  Copyright  2018, 2019, 2020 VMware Inc. All rights reserved.
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of the software in this file (the "Software"), to deal in the Software 
#  without restriction, including without limitation the rights to use, copy, 
#  modify, merge, publish, distribute, sublicense, and/or sell copies of the 
#  Software, and to permit persons to whom the Software is furnished to do so, 
#  subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in 
#  all copies or substantial portions of the Software.
#  
#  The names "VMware" and "VMware, Inc." must not be used to endorse or promote 
#  products derived from the Software without the prior written permission of 
#  VMware, Inc.
#  
#  Products derived from the Software may not be called "VMware", nor may 
#  "VMware" appear in their name, without the prior written permission of 
#  VMware, Inc.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
#  VMWARE,INC. BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#  IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#

<#
    .SYNOPSIS
     Sample Powershell script to deploy a VMware UAG virtual appliance to Microsoft Azure.
    .EXAMPLE
     .\uagdeployeaz.ps1 uag1.ini arm-template.json -rootPwd "password" -adminPwd "password" -ceipEnabled no
#>

param([string]$iniFile = "uag.ini",  [string]$jsonFile = "UAG-ARM-Template.json", [string] $rootPwd, [string] $adminPwd, [string] $ceipEnabled, [switch] $test)


#
# Function to validate Azure network settings from values specified in the .INI file
#
function ValidateNetworkSettings {
    Param ($settings, $nic)

    $virtualNetworkName = $settings.Azure.virtualNetworkName
    $subnetName = $settings.Azure.("subnetName"+$nic)
    $resourceGroupName = $settings.Azure.resourceGroupName
    ##ADDITION : separate variable for vNET Resource Group
    $vNetResourceGroupName = $settings.Azure.VirtualNetresourceGroupName ##ADDITION

    if ($virtualNetworkName.length -gt 0) {

        ##ADDITION : changed the ResourceGroupName parameter to $vNetResourceGroupName
        $vNet=Get-AzVirtualNetwork -Name $virtualNetworkName -ResourceGroupName $vNetResourceGroupName -ErrorAction Ignore -WarningAction SilentlyContinue
        If([string]::IsNullOrEmpty($vNet)) {    
            $msg = $error[0]
            WriteErrorString "Error: [Azure] virtualNetworkName ($virtualNetworkName) not found"
            Exit
        }
    } else {
        WriteErrorString "Error: [Azure] virtualNetworkName not specified"
        Exit
    }

    if ($subnetName.Length -gt 0) {
        $sn = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $vnet -ErrorAction Ignore -WarningAction SilentlyContinue
        if (!$sn) {
            WriteErrorString "Error: [Azure] subnetName$nic ($subnetName) not found in virtual network $virtualNetworkName"
            Exit
       }
    }

    $publicIPName = $settings.Azure.("publicIPAddressName"+$nic)

    if ($publicIPName.length -gt 0) {
    
        $pip=Get-AzPublicIpAddress -Name $publicIPName -ResourceGroupName $vNetResourceGroupName -ErrorAction Ignore -WarningAction SilentlyContinue
        If([string]::IsNullOrEmpty($pip)) {
            WriteErrorString "Error: [Azure] publicIPAddressName$nic ($publicIPName) not found"
            Exit
        }

        if ($pip.ipConfiguration.length -gt 0) {
            WriteErrorString "Error: [Azure] publicIPAddressName$nic ($publicIPName) is already in use"
            Exit
        }
    }

    $networkSecurityGroupName = $settings.Azure.("networkSecurityGroupName"+$nic)
    ##ADDITION : separate variable for NSG Resource Group
    $NSGresourceGroupName = $settings.Azure.("NSGResourceGroup"+$nic) ##ADDITION

    if ($networkSecurityGroupName.length -gt 0) {
        ########ADDITION : ADDED $NSGRESOURCEGROUPNAME because our NSGs are in a separate Resource Group from the other network objects
        $nsg=Get-AzNetworkSecurityGroup -Name $networkSecurityGroupName -ResourceGroupName $NSGresourceGroupName -ErrorAction Ignore -WarningAction SilentlyContinue
        If([string]::IsNullOrEmpty($nsg)) {
            WriteErrorString "Error: [Azure] networkSecurityGroupName$nic ($networkSecurityGroupName) not found"
            Exit
        }
    }
}

#
# Generate pseudo random password that meets the required Azure complexity rules
#
function GenerateAzureRandomPassword {
	$length = 12
	$charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]@#$%^()'.ToCharArray()
	$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
	$bytes = New-Object byte[]($length)
	$rng.GetBytes($bytes)
	$result = New-Object char[]($length)
	for ($i = 0 ; $i -lt $length ; $i++) {
	$result[$i] = $charSet[$bytes[$i]%$charSet.Length]
	}
	return "Password!"+(-join $result)
    
}

# doesn't delete anything, simply prints out a message in the event that there is already a VM with the same name
function DeleteExistingUAGResources {
    Param ($settings, $uagName)

    $resourceGroupName = $settings.Azure.resourceGroupName
    $VMInfo = Get-AzVM  -Name $uagName -ResourceGroupName $resourceGroupName -DisplayHint Expand -ErrorAction Ignore

    If ($VMInfo.Name) {
        write-host "There is an existing UAG VM ($uagName). Please make sure to delete the existing UAG and any of its associated resources before proceeding."
        Write-Host "Resources that may need deleted: VM Object, VM Disk, VM NICs"
        Exit
    }

}

#If the INI specifies to create a new LB this fxn will take care of that. If the INI specifies to add the UAG to the 
function LBModification{
    param($settings, $customPort="0")
    $customPort_Int = [System.Convert]::ToInt32($customPort)
    #if neither of these is true do nothing
    if(($settings.Azure.createLBifLBdoesnotexist -eq "true") -or ($settings.Azure.addUAGtoLB -eq "true")){

        $LBName = $settings.Azure.loadBalancerName
        if ($LBName.length -gt 0){
            Write-Host "Desired LB name is $LBName"
        } else {
            WriteErrorString "No LB Name (Azure.loadBalancerName) given in the INI file - breaking out of the LB Modification/Creation section."
            #If the LBName isn't given, end the function
            break
        }
    
        $LBRG = $settings.Azure.loadBalancerRG
        if ($LBName.length -gt 0){
            Write-Host "Desired LB Resource Group is $LBRG"
        } else {
            WriteErrorString "No LB NameAzure.loadBalancerRG given in the INI file - breaking out of the LB Modification/Creation section."
            #If the LBName isn't given, end the function
            break
        }
    
        $LoadBalancer = Get-AzLoadBalancer -Name $LBName -ResourceGroupName $LBRG
    
        if([string]::IsNullOrEmpty($LoadBalancer)) {
            
            if($settings.Azure.createLBifLBdoesnotexist -eq "true"){
                Write-Host "No Load Balancer found with name $LBName in RG $LBRG and createLBifLBdoesnotexist is true. Creating a new LB."

                #making sure the LB PIP RG is valid before passing it to the fxn
                $publicIPRG = $settings.Azure.LBPublicIPresourceGroup
                if ($publicIPRG.length -gt 0){Write-Host "Desired LB Public IP Resource Group is $publicIPRG"} 
                else {
                    WriteErrorString "No Azure.LBPublicIPresourceGroup given in the INI file - breaking out of the LB Modification/Creation section."
                    #If the LBName isn't given, end the function
                    break
                }   

                #Should also do a check to confirm that the Azure Location is valid, however, previous checks in the script ahve already confirmed this.

                $LoadBalancer = CreateLB -AzLocation $settings.Azure.location -LBName $LBName -LBResourceGroup $LBRG -LBPublicIPresourceGroup $publicIPRG
            }
            else{
                Write-Host "No Load Balancer found with name $LBName in RG $LBRG and createLBifLBdoesnotexist is false so ending the LB Section now."
                break
            }

        }
    
        if([string]::IsNullOrEmpty($LoadBalancer)) {
            $msg = $error[0]
            WriteErrorString "Error: [Azure] Load Balancer ($LBName) not found and could not be created - $msg"
            Write-Host "Ending the LB Section"
            break
        }
    
        Write-Host "Load Balancer has been found or created."
        
        if($settings.Azure.addUAGtoLB -eq "true"){

            #get NIC Object - WE KNOW NIC NAME BECAUSE WE SPECIFY IT IN THE ARM TEMPLATE
                # might be better to find the NIC from the VM Nic LIST in the long run
            $nic_Internet_name = "$($uagName)-NIC-Internet"
            $nic_Internet = Get-AzNetworkInterface -ResourceGroupName $VMresourceGroupName -Name $nic_Internet_name
        
            if ($nic_Internet.Name) {
                write-host "Found the VMs Internet NIC - proceeding with adding it to Load Balancer"
            }
            else{
                Write-Host "Error: [Azure] NIC not found. Ending the program."
                Exit
            }
        
            #get the backend pool of our Load Balancer object 
            $be_gen_name = "$($settings.Azure.loadBalancerName)-BP-UAGs"
            $be_gen = Get-AzLoadBalancerBackendAddressPoolConfig -Name $be_gen_name -LoadBalancer $LoadBalancer
        
            if ($be_gen.Name) {
                write-host "Found the Load Balancer's $($settings.Azure.loadBalancerName) common Backend Pool - proceeding with associating $($uagName)'s internet NIC"
            }
            else{
                Write-Host "Error: [Azure] $($settings.Azure.loadBalancerName) common Backend Pool not found. Ending the program."
                Exit
            }
        
            #get Front End pool of our load balancer object 
                ## Might need to get this a better way!
            $fe_name = "$($settings.Azure.loadBalancerName)-FE"
            $fe = Get-AzLoadBalancerFrontendIpConfig -Name $fe_name -LoadBalancer $LoadBalancer
        
            if ($fe.Name) {
                write-host "Found the Load Balancer's $($settings.Azure.loadBalancerName) Front End IP Config."
            }
            else{
                WriteErrorString "Error: [Azure] $($settings.Azure.loadBalancerName) Front End IP Config not found. Ending the program."
                Exit
            }
        
        
            # Create a new UAG Specific backend Pool
            $be_UAG_name = "$($settings.Azure.loadBalancerName)-BP-$($uagName)"
            #$be_UAG = New-AzLoadBalancerBackendAddressPoolConfig -Name $be_UAG_name
            Add-AzLoadBalancerBackendAddressPoolConfig -LoadBalancer $LoadBalancer -Name $be_UAG_name 
            Set-AzLoadBalancer -LoadBalancer $LoadBalancer
            # Need to do this Get because the Add-AzLoadBalancerBackendAddressPoolConfig returns the LB and not the BE Pool Config
            $be_UAG = Get-AzLoadBalancerBackendAddressPoolConfig -LoadBalancer $LoadBalancer -Name $be_UAG_name 
        
        
            If([string]::IsNullOrEmpty($be_UAG)) {    
                $msg = $error[0]
                WriteErrorString "Error: Failed to UAG Specific LB backend Pool $be_UAG_name - $msg"
                Exit
            }
        
        
            # add the Backend Pool to the IPConfiguration for the UAGs Internet NIC    
            $nic_Internet.IpConfigurations[0].LoadBalancerBackendAddressPools.Add($be_gen)
            # add the Backend Pool to the IPConfiguration for the UAGs Internet NIC    
            $nic_Internet.IpConfigurations[0].LoadBalancerBackendAddressPools.Add($be_UAG)
            Set-AzNetworkInterface -NetworkInterface $nic_Internet
        
        
            #create a new inbound Nat Rule for TCP 
            $NatRuleTCP_Name = "$($uagName)-NAT-TCP-$($customPort)"
            $NatRuleTCP = Add-AzLoadBalancerInboundNatRuleConfig -LoadBalancer $LoadBalancer -Name $NatRuleTCP_Name -Protocol "Tcp" -FrontendPortRangeStart $customPort_Int -FrontendPortRangeEnd $customPort_Int -BackendPort 443 -IdleTimeoutInMinutes 5 -FrontendIpConfiguration $fe -BackendAddressPool $be_UAG
            Set-AzLoadBalancer -LoadBalancer $LoadBalancer
        
        
            #create a new inbound Nat Rule for UDP
            $NatRuleUDP_Name = "$($uagName)-NAT-UDP-$($customPort)"
            $NatRuleUDP = Add-AzLoadBalancerInboundNatRuleConfig -LoadBalancer $LoadBalancer -Name $NatRuleUDP_Name -Protocol "Udp" -FrontendPortRangeStart $customPort_Int -FrontendPortRangeEnd $customPort_Int -BackendPort 8443 -FrontendIpConfiguration $fe -BackendAddressPool $be_UAG
            Set-AzLoadBalancer -LoadBalancer $LoadBalancer
        }
        else{
            Write-Host "The Azure.addUAGtoLB is not 'true' - will not add this UAG to the LB."
            break
        }
    }
}
    
# Source https://docs.microsoft.com/en-us/powershell/module/azurerm.network/new-azurermloadbalancer?view=azurermps-6.13.0
#Function that takes in an Azure Location, Load Balancer name, Load Balancer Resource Group, and Public IP Resource Group
function CreateLB{

    Param ($AzLocation, $LBName, $LBResourceGroup, $LBPublicIPresourceGroup)

    #must first create a new Public IP for the Load Balancer
    $publicIpName = $LBName + '-LB-PIP'
    $publicip = New-AzPublicIpAddress -ResourceGroupName $LBPublicIPresourceGroup -Name $publicIpName -Location $AzLocation -SKU Standard -AllocationMethod Static

    #must create the load balancer front end configuration
    $frontendname = $LBName + '-FE'
    $frontend = New-AzLoadBalancerFrontendIpConfig -Name $frontendname -PublicIpAddress $publicip

    #must create the load balancer backend config
    $backendname = $LBName + '-BP-UAGs'
    $backendAddressPool = New-AzLoadBalancerBackendAddressPoolConfig -Name $backendname

    #the different health probes that will be built for this LB: there is an additional option: "-ProbeCount 2" not sure if we need or what it shold be
    $probe_favicon = New-AzLoadBalancerProbeConfig -Name "HealthProbe_Favicon" -Protocol "HTTPS" -Port 443 -IntervalInSeconds 31 -RequestPath "/favicon.ico" -ProbeCount 2
    

    #Must build out the different LB rules
    $lbrule_TCP443_name = $LBName + '-TCP443-Rule'
    
    
    #add the load balancer rules to the existing LB
    $addrule = new-AzLoadBalancerRuleConfig -Name $lbrule_TCP443_name -FrontendIPConfiguration $frontend -BackendAddressPool $backendAddressPool -Probe $probe_favicon -Protocol "Tcp" -FrontendPort 443 -BackendPort 443 -IdleTimeoutInMinutes 15 -LoadDistribution SourceIP
    
    #build the actual LB object
    $lb = New-AzLoadBalancer -Name $LBName -ResourceGroupName $LBResourceGroup -SKU Standard -Location $AzLocation -FrontendIpConfiguration $frontend -BackendAddressPool $backendAddressPool -LoadBalancingRule $addrule -Probe $probe_favicon
    Write-Host "Lb is $($lb)"

    $lb = Get-AzLoadBalancer -Name $LBName -ResourceGroupName $LBResourceGroup
    Write-Host "Lb is $(Get-AzLoadBalancer -Name $LBName -ResourceGroupName $LBResourceGroup)"

    $lb
}

#creates a custom port of the format: 10X43
function CreateCustomPort{
    param($uagName)


    $customPortfe = "10"
    $customPortbe = "43"

    #extracts all non-zero digits from UAG Name
    $uagDigits = $uagName -replace "[^1-9]" , ''

    if ($uagDigits.length -eq 0){
        WriteErrorString "There are not digits in this UAG Name. Please correct the UAG name in the INI script to include at least 1 non-zero digit. Example: UAG-N-ZEUS-01"
        Exit
    }
    elseif ($uagDigits.length -gt 1){
        WriteErrorString "There are too many non-zero digits in this UAG Name. Please correct the UAG name in the INI script to include only 1 non-zero digit. Example: UAG-N-ZEUS-01"
        Exit
    }

    # CustomPort will equal '10X43'
    $customPort = $customPortfe + $uagDigits + $customPortbe
    return $customPort
}

function CreateWS1SAMLApp{
    param($UAGNAME, $UAGMGMTIP, $WS1AppCreationMod)

    $WS1Tenant= $settings.Horizon.WS1Tenant
    if ([string]::IsNullOrEmpty($WS1Tenant)){
        Write-host "INI File is missing the field for Horizon.WS1Tenant. Skipping the WS1 App Creation Function. "
        break
    }

    $WS1ClientID= $settings.Horizon.WS1ClientID
    if ([string]::IsNullOrEmpty($WS1ClientID)){
        Write-host "INI File is missing the field for Horizon.WS1ClientID. Skipping the WS1 App Creation Function. "
        break
    }
        
    $WS1SharedSecret= $settings.Horizon.WS1SharedSecret
    if ([string]::IsNullOrEmpty($WS1SharedSecret)){
        Write-host "INI File is missing the field for Horizon.WS1SharedSecret. PSkipping the WS1 App Creation Function. "
        break
    }

    $WS1AccessPolicy= $settings.Horizon.WS1AccessPolicy
    if ([string]::IsNullOrEmpty($WS1AccessPolicy)){
        Write-host "INI File is missing the field for Horizon.WS1AccessPolicy. Skipping the WS1 App Creation Function. "
        break
    }

    $WS1Groups= $settings.Horizon.WS1Grouplist
    if ([string]::IsNullOrEmpty($WS1Groups)){
        Write-host "INI File is missing the field for Horizon.WS1Grouplist. Skipping the WS1 App Creation Function. "
        break
    }

    # takes in the long GroupList string and splits it into an array of individual groups
    $WS1GroupList = $WS1Groups.Split("^") 
    
    <#
    $ScriptPath = $MyInvocation.MyCommand.Path
    $ScriptDir  = Split-Path -Parent $ScriptPath
    $WS1AppCreationMod=$ScriptDir+"\WS1AppCreationMod.psm1"
    #>

    if (!(Test-path $WS1AppCreationMod)) {
        Write-host "Error: PowerShell Module $WS1AppCreationMod not found." -foregroundcolor red -backgroundcolor black
        Exit
    }

    #this will import the module and run the Main function inside the module. All that's needed is to import the module
    Import-Module $WS1AppCreationMod -Force -ArgumentList $WS1Tenant,$WS1ClientID,$WS1SharedSecret,$UAGNAME,$UAGMGMTIP,$WS1AccessPolicy,$WS1GroupList
}

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  ENVIRONMENT SETUP ###################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################

#
# Load the dependent UAG PowerShell Module
#
if (-not (Get-InstalledModule -Name Az)) {
    Write-host "Error: Powershell module Az not found.
    Please look into details https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-8.2.0 for Az module installation.
    Alternatively Run the command 'Install-Module -Name Az -AllowClobber -Force' to install Az module and retry"
   Exit
}
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir  = Split-Path -Parent $ScriptPath
$uagDeployModule=$ScriptDir+"\uagdeploy.psm1"

#defnining the location of the WS1 Module
$WS1AppCreationMod=$ScriptDir+"\WS1AppCreationMod.psm1"


if (!(Test-path $uagDeployModule)) {
    Write-host "Error: PowerShell Module $uagDeployModule not found." -foregroundcolor red -backgroundcolor black
    Exit
}



import-module $uagDeployModule -Force -ArgumentList $awAPIServerPwd, $awTunnelGatewayAPIServerPwd, $awTunnelProxyAPIServerPwd, $awCGAPIServerPwd, $awSEGAPIServerPwd



Write-host "Unified Access Gateway (UAG) virtual appliance Microsoft Azure deployment script"

if (!(Test-path $iniFile)) {
    WriteErrorString "Error: Configuration file ($iniFile) not found."
    Exit
}

$settings = ImportIni $iniFile

$uagName=$settings.General.name

#
# Login if needed
#

Write-Host -NoNewline "Validating Azure subscription .."

try {
    $out=Get-AzSubscription -ErrorAction Ignore
    }
     
catch {
    Connect-AzAccount
}

Write-Host -NoNewline "."

if (!$out) {
    try {
        $out=Get-AzSubscription -ErrorAction Ignore
        }
    
    catch {
        WriteErrorString "Error: Failed to log in to Azure."
        Exit
    }
}

Write-Host -NoNewline "."

if ($settings.Azure.subscriptionID -gt 0) {

    try {
        $out=Set-AzContext -Subscription $settings.Azure.subscriptionID
    }

    catch {
        WriteErrorString "Error: Specified subscriptionID not found."
        Exit
    }
} else {
     WriteErrorString "Error: [Azure] subscriptionID not specified."
     Exit
}

Write-Host ". OK"

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  CUSTOM DATA CREATION BEGINNING ######################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################


$deploymentOption=GetDeploymentSettingOption $settings

if ($uagName.length -gt 32) { 
    WriteErrorString "Error: Virtual machine name must be no more than 32 characters in length"
    Exit
}

if (!$uagName) {
    WriteErrorString "Error: [General] name not specified"
    Exit
}

if (!$rootPwd) {
    $rootPwd = GetRootPwd $uagName $settings
}

if (!$adminPwd) {
    $adminPwd = GetAdminPwd $uagName $settings
}

if (!$ceipEnabled) {
    $ceipEnabled = GetCeipEnabled $uagName
}


###################################################################  Custom Port + Modify Tunnel/Blast URL ######################################################################
if($settings.Azure.addUAGtoLB -eq "true"){

    if([string]::IsNullOrEmpty($settings.Azure.UAGCustomPort)){
        $customPort = CreateCustomPort($uagName)
    }
    else{
        $customPort = $settings.Azure.UAGCustomPort
        #COULD IMPLEMENT: if customPort: is non-numeric, is greater than 5 chars, is less than 1 then exit the script 
    }
    ### Grab the Hostname and add the custom information
    $settings.Horizon.blastExternalUrl = "https://$($settings.Horizon.blastExternalUrl):$($customPort)?udpport=$($customPort)"
    $settings.Horizon.tunnelExternalUrl = "https://$($settings.Horizon.tunnelExternalUrl):$($customPort)"
}
else{
    Write-Host "The Azure.addUAGtoLB is not 'true' - will not use a custom port for the Tunnel and Blast External URLs."
    $settings.Horizon.blastExternalUrl = "https://$($settings.Horizon.blastExternalUrl):8443"
    $settings.Horizon.tunnelExternalUrl = "https://$($settings.Horizon.tunnelExternalUrl):443"
}

Write-Host "Blast External URL is $($settings.Horizon.blastExternalUrl)" 
Write-Host "Tunnel External URL is $($settings.Horizon.tunnelExternalUrl)" 
##########################################################################################################################################################################


$settingsJSON=GetJSONSettings $settings $newAdminUserPwd

SetUp

Write-Host "Made it past the setup function"

$ovfFile = "${env:APPDATA}\VMware\$uagName.cfg"
([string[]]("deploymentOption="+"$deploymentOption")) | Set-Content -Path $ovfFile

$dns=$settings.General.dns
if ($dns.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("DNS="+"$dns"))
}

$rootPasswordExpirationDays=$settings.General.rootPasswordExpirationDays
if ($rootPasswordExpirationDays.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("rootPasswordExpirationDays="+"$rootPasswordExpirationDays"))
}

$passwordPolicyMinLen=$settings.General.passwordPolicyMinLen
if ($passwordPolicyMinLen.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("passwordPolicyMinLen="+"$passwordPolicyMinLen"))
}

$passwordPolicyMinClass=$settings.General.passwordPolicyMinClass
if ($passwordPolicyMinClass.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("passwordPolicyMinClass="+"$passwordPolicyMinClass"))
}

$passwordPolicyDifok=$settings.General.passwordPolicyDifok
if ($passwordPolicyDifok.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("passwordPolicyDifok="+"$passwordPolicyDifok"))
}

$passwordPolicyUnlockTime=$settings.General.passwordPolicyUnlockTime
if ($passwordPolicyUnlockTime.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("passwordPolicyUnlockTime="+"$passwordPolicyUnlockTime"))
}

$passwordPolicyFailedLockout=$settings.General.passwordPolicyFailedLockout
if ($passwordPolicyFailedLockout.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("passwordPolicyFailedLockout="+"$passwordPolicyFailedLockout"))
}


$adminPasswordFailedLockoutCount=$settings.General.adminPasswordPolicyFailedLockoutCount
if ($adminPasswordFailedLockoutCount.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("adminPasswordPolicyFailedLockoutCount="+"$adminPasswordFailedLockoutCount"))
}

$adminPasswordMinLen=$settings.General.adminPasswordPolicyMinLen
if ($adminPasswordMinLen.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("adminPasswordPolicyMinLen="+"$adminPasswordMinLen"))
}

$adminPasswordLockoutTime=$settings.General.adminPasswordPolicyUnlockTime
if ($adminPasswordLockoutTime.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("adminPasswordPolicyUnlockTime="+"$adminPasswordLockoutTime"))
}

$adminSessionIdleTimeoutMinutes=$settings.General.adminSessionIdleTimeoutMinutes
if ($adminSessionIdleTimeoutMinutes.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("adminSessionIdleTimeoutMinutes="+"$adminSessionIdleTimeoutMinutes"))
}

$rootSessionIdleTimeoutSeconds = ValidateRootSessionIdleTimeoutSeconds $settings
if ($rootSessionIdleTimeoutSeconds.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("rootSessionIdleTimeoutSeconds="+"$rootSessionIdleTimeoutSeconds"))
}

$defaultGateway=$settings.General.defaultGateway
if ($defaultGateway.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("defaultGateway="+"$defaultGateway"))
}

$v6DefaultGateway=$settings.General.v6DefaultGateway
if ($v6defaultGateway.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("v6defaultGateway="+"$v6defaultGateway"))
}

$forwardrules=$settings.General.forwardrules
if ($forwardrules.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("forwardrules="+"$forwardrules"))
}

$routes0=$settings.General.routes0
if ($routes0.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("routes0="+"$routes0"))
}

$routes1=$settings.General.routes1
if ($routes1.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("routes1="+"$routes1"))
}

$routes2=$settings.General.routes2
if ($routes2.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("routes2="+"$routes2"))
}

$policyRouteGateway0=$settings.General.policyRouteGateway0
if ($policyRouteGateway0.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("policyRouteGateway0="+"$policyRouteGateway0"))
}

$policyRouteGateway1=$settings.General.policyRouteGateway1
if ($policyRouteGateway1.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("policyRouteGateway1="+"$policyRouteGateway1"))
}

$policyRouteGateway2=$settings.General.policyRouteGateway2
if ($policyRouteGateway2.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("policyRouteGateway2="+"$policyRouteGateway2"))
}

if ($ceipEnabled -eq $true) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("ceipEnabled=true"))
}

if ($settings.General.tlsPortSharingEnabled -eq "true") {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("tlsPortSharingEnabled=true"))
}

if ($settings.General.sshEnabled -eq "true") {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("sshEnabled=true"))
}

if ($settings.General.sshPasswordAccessEnabled -eq "false") {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("sshPasswordAccessEnabled=false"))
}

if ($settings.General.sshKeyAccessEnabled -eq "true") {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("sshKeyAccessEnabled=true"))
}

$sshBannerText=ReadLoginBannerText $settings
if ($sshBannerText.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("sshLoginBannerText=" + "$sshBannerText"))
}

$secureRandomSrc=ReadSecureRandomSource $settings
if ($secureRandomSrc.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("secureRandomSource=" + "$secureRandomSrc"))
}

[IO.File]::AppendAllLines($ovfFile, [string[]]("rootPassword="+"$rootPwd"))

if ($adminPwd.length -gt 0) {
    [IO.File]::AppendAllLines($ovfFile, [string[]]("adminPassword="+"$adminPwd"))
}

$enabledAdvancedFeatures = $settings.General.enabledAdvancedFeatures
if($enabledAdvancedFeatures.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("enabledAdvancedFeatures="+"$enabledAdvancedFeatures"))
}

# Adding ConfigData related propertiesFile
$configURL = $settings.General.configURL
if($configURL.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("configURL="+"$configURL"))
}

$configKey = $settings.General.configKey
if($configKey.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("configKey="+"$configKey"))
}

$configURLThumbprints = $settings.General.configURLThumbprints
if($configURLThumbprints.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("configURLThumbprints="+"$configURLThumbprints"))
}

$configURLHttpProxy = $settings.General.configURLHttpProxy
if($configURLHttpProxy.length -gt 0){
    [IO.File]::AppendAllLines($ovfFile, [string[]]("configURLHttpProxy="+"$configURLHttpProxy"))
}

$imageURI = $settings.Azure.imageURI

if ($imageURI.length -eq 0) {
    WriteErrorString "Error: [Azure] imageURI not found"
    [IO.File]::Delete($ovfFile)
    Exit
}

$location = $settings.Azure.location

Write-Host "Set the Azure Location"

if ($location.length -gt 0) {
    $res =  Get-AzResourceProvider -Location $settings.Azure.location -ProviderNameSpace Microsoft.Compute
    If([string]::IsNullOrEmpty($res)) {    
        WriteErrorString "Error: [Azure] location ($location) not found"
        $locations = Get-AzResourceProvider -ProviderNameSpace Microsoft.Compute
        $locationNames = $locations[0].Locations
        WriteErrorString "Specify a location from the following list:"
        for ($i=0; $i -lt $locations[0].Locations.Count; $i++) {
            write-host $locations[0].Locations[$i]
        }
        [IO.File]::Delete($ovfFile)
        Exit
    }
} else {
    WriteErrorString "Error: [Azure] location not specified"
    [IO.File]::Delete($ovfFile)
    Exit
}

$resourceGroupName = $settings.Azure.resourceGroupName

if ($resourceGroupName.Length -gt 0) {
    $out = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    if ($out.ResourceId.Length -eq 0) {
        $out = New-AzResourceGroup -Name $resourceGroupName -Location $location

        $out
        if ($out.ResourceId.Length -eq 0) {
            WriteErrorString "Error: [Azure] resourceGroupName ($resourceGroupName) not found and could not be created"
            [IO.File]::Delete($ovfFile)
            Exit
        }
    }
} else {
     WriteErrorString "Error: [Azure] resourceGroupName not specified."
    [IO.File]::Delete($ovfFile)
     Exit
}

#Not entirely necessary but the script is written presuming this variable exists
$VMresourceGroupName = $settings.Azure.resourceGroupName


$storageAccountName = $settings.Azure.storageAccountName
$storageAccountRG = $settings.Azure.storageAccountRG

if (($storageAccountName.length -gt 0) -and ($storageAccountRG.length -gt 0)) {
    $storageAcc = Get-AzStorageAccount -ResourceGroupName $storageAccountRG -Name $storageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If($storageAcc.Id.Length -eq 0) { 
        $storageAcc = New-AzStorageAccount -ResourceGroupName $storageAccountRG -Name $storageAccountName -Location $location -SkuName Standard_LRS -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($storageAcc.Id.Length -eq 0) {
            $msg = $error[0]
            WriteErrorString "Error: [Azure] storageAccountName ($storageAccountName) not found and could not be created - $msg"
            [IO.File]::Delete($ovfFile)
            Exit
        }
    }
} else {
    WriteErrorString "Error: [Azure] storageAccountName or storageAccountRG not specified"
    [IO.File]::Delete($ovfFile)
    Exit
}

$diskStorageContainer = $settings.Azure.diskStorageContainer.ToLower()
if ($diskStorageContainer.length -gt 0) {
    $container = Get-AzRmStorageContainer -Name $diskStorageContainer -ResourceGroupName $storageAccountRG -StorageAccountName $storageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    If($container.Name.Length -eq 0) { 
        $container = New-AzRmStorageContainer -Name $diskStorageContainer -ResourceGroupName $storageAccountRG -StorageAccountName $storageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($container.Name.Length -eq 0) {
            $msg = $error[0]
            WriteErrorString "Error: [Azure] diskStorageContainer ($diskStorageContainer) not found and could not be created - $msg"
            [IO.File]::Delete($ovfFile)
            Exit
        }
    }
} else {
    WriteErrorString "Error: [Azure] diskStorageContainer not specified"
    [IO.File]::Delete($ovfFile)
    Exit
}

Write-Host "Made it past the DiskStorageContainer"

DeleteExistingUAGResources $settings $uagName

$vmSize = $settings.Azure.vmSize
if ($vmSize.length -gt 0) {
    write-host "Deploying $uagName as $vmSize"
} else {
    $vmSize = "Standard_A4_v2"
}

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  VM OBJECT CREATION ##################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################

switch -Wildcard ($deploymentOption) {

    'onenic*' {
        # ADDITION - VALIDATENETWORKSETTINGS checks whether the network settings in the INI are valid - should probably keep
        ValidateNetworkSettings $settings "0"
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode0=DHCPV4+DHCPV6"))
        $customConfigEntry0 = GetCustomConfigEntry $settings "0"
        if ($customConfigEntry0.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry0))
        }
    }
    'twonic*' {
        # ADDITION - VALIDATENETWORKSETTINGS checks whether the network settings in the INI are valid - should probably keep
        ValidateNetworkSettings $settings "0"
        ValidateNetworkSettings $settings "1"

        # ADDITION - the below lines further add to custom data
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode0=DHCPV4+DHCPV6"))

        # ADDITION - the below lines further add to custom data
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode1=DHCPV4+DHCPV6"))

        $customConfigEntry0 = GetCustomConfigEntry $settings "0"
        if ($customConfigEntry0.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry0))
        }
        $customConfigEntry1 = GetCustomConfigEntry $settings "1"
        if ($customConfigEntry1.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry1))
        }
    }
    'threenic*' {
        ValidateNetworkSettings $settings "0"
        ValidateNetworkSettings $settings "1"
        ValidateNetworkSettings $settings "2" 

        # ADDITION - the below lines further add to custom data
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode0=DHCPV4+DHCPV6"))

        # ADDITION - the below lines further add to custom data
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode1=DHCPV4+DHCPV6"))

        # ADDITION - the below lines further add to custom data
        [IO.File]::AppendAllLines($ovfFile, [string[]]("ipMode2=DHCPV4+DHCPV6"))

        $customConfigEntry0 = GetCustomConfigEntry $settings "0"
        if ($customConfigEntry0.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry0))
        }
        $customConfigEntry1 = GetCustomConfigEntry $settings "1"
        if ($customConfigEntry1.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry1))
        }
        $customConfigEntry2 = GetCustomConfigEntry $settings "2"
        if ($customConfigEntry2.length -gt 0) {
            [IO.File]::AppendAllLines($ovfFile, [string[]]($customConfigEntry2))
        }
    }
    default {
        WriteErrorString "Error: Invalid deploymentOption ($deploymentOption)."
        [IO.File]::Delete($ovfFile)
        Exit  
    }
}

Write-Host ". OK"

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  CUSTOM DATA CREATION END ############################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################


$pwd = GenerateAzureRandomPassword
$adminuser = "azureuser"
$securePassword = ConvertTo-SecureString $pwd -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($adminuser, $securePassword)

[IO.File]::AppendAllLines($ovfFile, [string[]]("settingsJSON="+"$settingsJSON"))

$ovfProperties = Get-Content -Raw $ovfFile

$customData = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($ovfProperties))


##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  DEPLOY VM W/ ARM TEMPLATE ############################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################

#JSON Template Params as Hash Table
    $templateParams = @{
        "adminUsername"=$adminuser
        "adminPassword"=$pwd
        "location"=$location
        "customdata"=$customData
        "vmName"=$uagName
        "imageResourceGroup"=$VMresourceGroupName #uses the same RG as the UAG VM
        "imageURI"=$imageURI #the blob URI of the VHD - the location of the VHD used to create the VM image
        "vhd_uag"=$settings.Azure.vhduag
        "vmSize"=$vmSize
        "availabilitySet_Name"=$settings.Azure.availabilitySetName
        "availabilitySet_RG"=$settings.Azure.availabilitySetRG
        "storageAccount_Name"=$storageAccountName
        "StorageAccount_RG"=$storageAccountRG
        "vNet_Name"=$settings.Azure.virtualNetworkName
        "vNet_RG"=$settings.Azure.VirtualNetresourceGroupName
        "NSGInternet_Name"=$settings.Azure.networkSecurityGroupName0
        "NSGInternet_RG"=$settings.Azure.NSGResourceGroup0
        "NSGMgmt_Name"=$settings.Azure.networkSecurityGroupName1
        "NSGMgmt_RG"=$settings.Azure.NSGResourceGroup1
        "SubnetInternet_Name"=$settings.Azure.subnetName0
        "SubnetMgmt_Name"=$settings.Azure.subnetName1   
    } 



Write-Host "Congratulations you have made it to the ARM Deployment."


if($test){
    Test-AzResourceGroupDeployment -ResourceGroupName $VMresourceGroupName -TemplateFile $jsonFile -TemplateParameterObject $templateParams 
    Write-Host "Ran the ARM Deployment in Test mode"
    [IO.File]::Delete($ovfFile)
}
else{
    New-AzResourceGroupDeployment -ResourceGroupName $VMresourceGroupName -TemplateFile $jsonFile -TemplateParameterObject $templateParams 
    write-host "Deployed $uagName successfully to Azure resource group $VMresourceGroupName"
    [IO.File]::Delete($ovfFile)
}

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  SET VM NICS TO STATIC ############################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
if($test){
    Write-Host "Ran the Script in Test mode: skipping the -----------------Setting VMs NICs to Static----------------- section" -ForegroundColor Yellow -BackgroundColor Gray
}
else{
    
    Write-Host "-----------------Setting VMs NICs to Static-----------------"

    $vm = Get-AzVM  -Name $uagName -ResourceGroupName $resourceGroupName -DisplayHint Expand -ErrorAction Ignore

    if ($vm.Name) {
        write-host "Found the VM Object - proceeding with getting its NICs"
    }
    else{
        Write-Host "Error: [Azure] VM not found. Ending the program. You must set the NICs to static manually. "
        Exit
    }

    $nics = $vm.NetworkProfile.NetworkInterfaces
    if ($nics) {
        write-host "Found the VMs NICs - proceeding with setting them to Static"
    }
    else{
        Write-Host "Error: [Azure] NICs not found. Ending the program. You must set the NICs to static manually. "
        Exit
    }

    #maybe use this opportunity to create Global objects for Mgmt NIC and Internet NIc THAT Will be used in the two below sections
    foreach($nic in $nics) {
        $nicname = $nic.Id 
        $a = $nicname.Split("/")
        $index = $a.count - 1
        $nicname = $a.GetValue($index)
        $nicobj = Get-AzNetworkInterface -Name $nicname -ResourceGroupName $VMresourceGroupName
        $nicobj.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
        Set-AzNetworkInterface -NetworkInterface $nicobj
        Write-Host "$($nicname) has an IpConfig property of $($nicobj.IpConfigurations[0].PrivateIpAllocationMethod)"
    }

    Write-Host "Finished Modifying the NICs' IPConfigs"
}

##########################################################################################################################################################################
##########################################################################################################################################################################
###################################################################  Create Workspace One Access Web App #################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################

if($test){
    Write-Host "Ran the Script in Test mode: skipping the -----------------Create Workspace One Access Web App----------------- section" -ForegroundColor Yellow -BackgroundColor Gray
}
else{
    $CreateWS1SAMLApp = $settings.Horizon.CreateWS1SAMLApp

    #Only if this INI field is set to true will the WS1 creation Proceed
        #using a While so I can break out of the WS1 App Creation Block
    while($CreateWS1SAMLApp -eq "true"){
        # NEED THIS TO PASS THE mGMT IP TO THE WS1 FXN
        #get NIC Object - WE KNOW NIC NAME BECAUSE WE SPECIFY IT IN THE ARM TEMPLATE
            # might be better to find the NIC from the VM Nic LIST in the long run
        $nic_Mgmt_name = "$($uagName)-NIC-Mgmt"
        $nic_Mgmt = Get-AzNetworkInterface -ResourceGroupName $VMresourceGroupName -Name $nic_Mgmt_name
        if ($nic_Mgmt.Name){
            Write-host "Found the UAGs Mgmt NIC. Getting the IP now. "}
        else{
            Write-Host "Error: [Azure] NIC not found."
            Break
        }
        #$nic_Mgmt_IP = $nic_Mgmt.IpConfigurations[0].PrivateIpAddress
            #OR #depends on whether each IP config can have a private IP or theres just one private IP - https://social.technet.microsoft.com/wiki/contents/articles/52870.powershell-finding-ip-of-vm-from-azure-portal-az-module.aspx
        $nic_Mgmt_IP = $nic_Mgmt.IpConfigurations.PrivateIpAddress 
        $nic_Mgmt_IP = $nic_Mgmt_IP.ToString()
        

        #call the WS1 App creation function
        CreateWS1SAMLApp -UAGNAME $uagName -UAGMGMTIP $nic_Mgmt_IP -WS1AppCreationMod $WS1AppCreationMod
        Break
    }
    if($CreateWS1SAMLApp -ne "true"){
        Write-Host "Skipping the WS1 SAML Web App Creation since the INI Field Horizon.CreateWS1SAMLApp is not true."
    }
}


##########################################################################################################################################################################
##########################################################################################################################################################################
########################################################################  Create LB and/or Add UAG to LB #################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
if($test){
    Write-Host "Ran the Script in Test mode: skipping the -----------------Create LB and/or Add UAG to LB----------------- section" -ForegroundColor Yellow -BackgroundColor Gray
}
else{
    # Run the LB Modification function - this function will determine whether an LB should be created and whether the newly created UAG should be added to the LB
    LBModification -settings $settings -customPort $customPort
}


########################################################################  Script End #################################################################################


Write-Host "----------------------------------------------------------------------------------------- " -foregroundcolor Green -backgroundcolor Blue
Write-Host "----------------------------------------------------------------------------------------- " -foregroundcolor Green -backgroundcolor Blue
Write-Host "The Script has completed. Please validate all of the settings have been applied properly. " -foregroundcolor Green -backgroundcolor Blue
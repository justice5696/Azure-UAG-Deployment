# Azure-UAG-Deployment
## Description: Manual for deploying a VMware UAG to Azure using the script in this repo
- This package is used to deploy a VMware UAG into Azure. This script is different from the VMware supplied UAG Deployment script for Azure in that it uses an ARM template to Deploy the UAG with a Managed Disk and in an Availablity Set.
- This script additionally sets the UAG NICs' IP Configurations to Static type (this is easy to remove from the script if needed). 
    - The NICs are first deployed as Dynamic so that they get an IP from the Subnet, then we change the NIC to Static so the Private IP does not change.
- This script uses only the Az module (and not the deprecated AzureRM Module)
- This script optionally can perform the two following capabilties: 
    1. Deploy an Azure Load Balancer using the methodology described here: https://techzone.vmware.com/resource/load-balancing-unified-access-gateway-horizon#method-2---multiple-port-number-groups
        - The Azure Load Balancer will be created if an LB with the specified name does not already exist (assuming the createLBifLBdoesnotexist INI flag is set to true)
            - The LB will be deployed initially with a single Front End IP Configuration with a single Public IP. 
            - It will initially have a single Backend Address Pool associated with it, and a single Probe that probes on HTTPS',443, 'GET /favicon.ico'
            - A single load balancing rule will be created for TCP 443 with the above Probe, Front End Configuration, and Backend Address Pool
        - If the addUAGtoLB INI flag is set to true, then when the UAG VM is created, it will automatically be added to the above Azure Load Balancer
            - This will result in the automatic building of a new Backend Address Pool Config with a Custom Port (generally a 10X43 port), and 2 Inbound NAT Rules.
            - The UAGs Internet NIC will be associated with each of the Backend Address Pool Configs.
            - Two New Inbound NAT Rules will be created NATting the Custom Port to both TCP443 or UDP8443 and these NAT Rules will be associated with the Custom Port Backend Address Pool Config.
        - Benefits of this methodology: In its current state, the Azure Load Balancer does not support failures of UAGs in a healthy way. If the UAG becomes 'Unhealthy' then Azure stops sending all traffic to the UAG (rather than only stopping new connections). This ultimately prevents the Quiesce Mode on the UAG from being used - which is a means of being able to remove a UAG from the Load Balancing Pool in a healthy way. By using the LB methodology deployed by this script, the UAG can handle an unhealthy status in a better way.
    2. Create a new Workspace One Access SAML Application to support authentication requests from the UAG for authentication into the UAG Admin (9443) Portal. (More details in the 'Fill out the INI file' subsection.)


## Software Requirements
- Running the Script: 
    - Windows 10/11 or Windows Server 2016/2019/2022 (Tested)
    - PowerShell 7 recommended (Tested)
- UAG Supported Versions: 
    - 2203.1 (Tested)
    - Should be possible on most UAG versions newer then 2203.1 but this is untested
- Workspace One Access Versions
    - All Workspace One Access SaaS tenants with the new UI (Tested)
    - Workspace One Access On-Prem 2209+ (Tested)
    - Older versions of Workspace One Access will likely work but are untested.



## Prerequisites

#### Fill out the INI file
- Any field commented with Mandatory must be filled out.
- Pay close attention to the Comments at the beginning of the INI file regarding Syntax (very important)
- Set the fields for Azure Load Balancer Deployment and Workspace ONE App Deployment. Within the [Azure] Section there are two important clusters of fields relating to the Azure Load Balacer deployment and the Workspace ONE Access SAML App Creation
    1. In the Azure Load Balancer section you can set whether you want an Azure LB to be created if one does not exist, and whehter you want the UAG added to that LB
    2. In the Workspace ONE Access section you can set whether you want a Workspace ONE Access SAML app to be created that will enable SAML Auth Requests from the UAG to be fulfilled by the specified Workspace ONE Access tenant. You need to specify the Workspace ONE OAuth Shared Secret and Client ID in order for the script to make the API calls to the Workspace ONE Access Tenant - see the below 'Getting the Workspace ONE Client ID and Shared Secret' for information on getting these values.
- There are links at the top of the INI file with information on some of the fields of the INI file
- IMPORTANT: The [General].name field should be changed between each deployment. If you attempt to deploy a UAG with the same name as an existing UAG in a Resource Group, you will trigger the DeleteExistingUAGResources function. Previously this function would actually delete the original UAG and all of its resources. This iteration of the script just prints out a message that tells you to fix the conflict and rerun the script, then it Exits the Function.

#### Getting the Workspace ONE Client ID and Shared Secret 
- If you do not have a Workspace ONE Access OAuth Token already created and the corresponding Client ID and Shared Secret, then you will have to generate a new Token.
    - More Information: https://techzone.vmware.com/blog/lets-git-committed-resources-getting-started-workspace-one-access-apis
- Generating a new OAuth Token:
    1. Log into the Workspace ONE Access Portal and navigate to the administrative portal. 
    2. Click on the ***Settings*** tab.
    3. Click on ***OAuth 2.0 Management***
    4. Click on ***ADD CLIENT***
    5. Set the following fields:
        - ***Access type*** : ***Service Client Token***
        - ***Client ID*** : Choose some unique ID that will identify your token
        - ***Scope*** : Enable ***Admin***
        - ***Access token time-to-live (TTL)*** : 3 hours 
        - ***Idel token TTL*** : 10 days 
        - ***Token type*** : Bearer
    6. Click Save once the fields are filled out. At this point ***YOU MUST*** copy down the Shared Secret somewhere as this is the only time that Workspace ONE will display this value.
        - This Shared Secret (in conjunction with your Client ID) will give someone full, unrestricted, admin access to your Workspace ONE Access tenant. ***SAVE THIS SHARED SECRET SOMEWHERE SAFE***


#### Create the ceritficate files 
- To consistently deploy UAGs with their SSL certificates already installed, you must convert the certificate and key to PEM files. 
    - The PowerShell Deployment Script technically supports PFX certificates, but I have noticed issues when using this method.
- Get a full-chain PFX version of your UAG SSL certificate with the Private Key included. This Certificate will cover the UAG's listening address for Horizon Connections.
- Must have a Linux/Unix machine with OpenSSL installed
    - Do not use Windows versions of OpenSSL. There have been issues with RSA Conversions not actually working. 
    - If a Linux machine is unavailable, it is free to create an AWS Free Tier account and deploy a free Amazon Linux Machine.
- Steps to convert the Full-Chain PFX Certificate with a Private Key to PEM Files:
    1. Copy the PFX file to the local file system of the Linux machine: exa. /tmp/PFXCert.pfx
    2. Open and Administrator Terminal and CD to the same directory: exa. cd /tmp/
    3. Run the following three commands:
        1. `openssl pkcs12 -in PFXCert.pfx -nokeys -out PEMCert.pem`
            - This will prompt for the pfx file’s private key password and will output a PEM file containing the entire certificate chain (with no keys)
        2. `openssl pkcs12 -in PFXCert.pfx -nodes -nocerts -out PEMKey.pem`
            - This will prompt for the pfx file’s password and will output a PEM file containing the certificate's Private Key (with no certificates)
        3. `openssl rsa -in PEMKey.pem -check -out PEMKey_RSA.pem`
            - This will take in the KEY file and convert it to an RSA Version KEY File.
            - This is the KEY file that will actually be passed to the UAG PowerShell Deployment Script
    4. Open the PEMKey_RSA.pem with a text editor and change the lines: 
        - ***BEGIN PRIVATE KEY*** with ***BEGIN RSA PRIVATE KEY***
        - ***END PRIVATE KEY*** with ***END RSA PRIVATE KEY***
- The PEMKey_RSA.pem and PEMCert.pem files are the files that will be passed to the UAG PowerShell Deployment Script via the INI file.


#### Configure SAML for the UAG Admin portal 
- This will be used to configure the UAGs for SAML Authentication to the UAG Admin portal (ie. https://<UAG-IP>:9443/admin). 
    - NOTE: It is possible to configure other IDPs for UAG SAML Auth, but this script is only designed to build a Web App in Workspace ONE Access. If you choose to use another IDP, you must not fill out the other Workspace ONE fields in the INI file (specifically: CreateWS1SAMLApp, WS1Tenant, WS1ClientID, WS1SharedSecret, WS1AccessPolicy, WS1Grouplist). Instead, only cnfigure the [IDPExternalMetadata1] and [adminSAMLSettings] sections with your IDP information. You will then have to manually create an application in that IDP to accept the authentication requests from the UAG.
- Within the [IDPExternalMetadata1] section there is a field called ***metadataXmlFile*** - this should be a path to an XML file containing your IDP's metadata. 
- To get the Workspace ONE Access IDP Metadata XML File follow the following steps:
    1. Log into the Workspace ONE Access Portal and navigate to the administrative portal. 
    2. Click on ***Resources*** > ***Web Apps***
    3. Click on the ***Settings*** button within the ***Web Apps*** page 
    4. Click on the ***SaaS Apps*** > ***SAML Metadata*** tab 
    5. Click on the ***Identity Provider (Idp) metadata*** link 
        - Alternatively just navigate directly to ***https://<WS1 Tenant>/SAAS/API/1.0/GET/metadata/idp.xml***
    6. Once the XML page has opened in the browser, save the page as an XML file and put the XML file somewhere accessible
    7. Add the path to the XML file to your INI under the ***[IDPExternalMetadata1] metadataXmlFile*** field


#### Place the UAG VHD into an Azure Storage Account
- The UAG VHD image file is used to create new UAGs. This image file must be downloaded from VMware and uploaded to a specifically named location within an Azure Storage Account. 
- More information on the Storage Account Requirements: https://docs.vmware.com/en/Unified-Access-Gateway/2209/vmware-uag-powershell-azure-deployment/GUID-9576E918-5B2C-42EA-88B5-B06E75F1E8AD.html
- Steps for uploading the UAG VHD file:
    1. Add a storage account, and a blob container called vhds within that storage account. It is to store the Unified Access Gateway images. You can add using the Azure Portal web interface, or by running the PowerShell commands as in this example: 
        1. `New-AzStorageAccount -ResourceGroupName $resourceGroup -AccountName uagstore -Location $location -SkuName Standard_LRS`
        2. `New-AzRmStorageContainer -Name vhds -ResourceGroupName $resourceGroup -StorageAccountName uagstore`
    2. Download the version of the UAG VHD file from VMware that you want to deploy and put it at some accessible local path (exa. "E:\UAGImages\<vhd file name>").
    3. Use the following example PowerShell commands to upload the .vhd image to the vhds container created earlier. 
        1. `$imageURI = "https://<storage_account_name>.blob.core.windows.net/vhds/<vhd file name>"`
        2. `$imagePath = "<local path to the downloaded UAG vhd file>"`
        3. `Add-AzVhd -ResourceGroupName $resourceGroup -LocalFilePath $imagePath -Destination $imageURI -NumberOfUploaderThreads 32`
    4. Confirm that the UAG VHD file has been correctly uploaded to the Azure Storage Account in the correct location


## Deployment: How to run this script
1. Copy the files locally to a folder on your machine (exa. C:\Temp). Files to copy: uagdeploy.psm1, uagdeployaz.ps1, WS1AppCreationMod.psm1, UAG-PSDeployment-ARM.ini, UAG-ARM-Template.json
    - Do not change any of the names of these files as there could be unforeseen consequences
2. Open an Administrator PowerShell Window
3. Run the `Connect-Az` command to connect to the correct Azure subscription 
4. Change directory to the local folder that has all the copied files
5. Run the following command: `.\uagdeployaz.ps1 .\UAG-PSDeployment-ARM.ini .\UAG-ARM-Template.json [ -rootPwd <passwd>] [ -adminPwd <passwd>] [ -CEIPEnabled true|false ] [ -test ]`
    - The -test flag will collect and validate a lot of the given data but nothing will be created in Azure or Workspace One Access


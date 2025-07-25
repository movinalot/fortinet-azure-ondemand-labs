<#
    .DESCRIPTION
        Manage Azure AD Training Users and On Demand Labs

    .NOTES
        AUTHOR: jmcdonough@fortinet.com
        LAST EDIT: July 23, 2025
#>

# Can be run via WebHook or from Cmd line.
param(
	[CmdletBinding()]
	[Parameter(Mandatory = $false)]
	[ValidateSet("Create", "Delete", "List")]
	[string] $UserOp,

	[Parameter(Mandatory = $false)]
	[string] $UserName,

	[Parameter(Mandatory = $false)]
	[string] $UserEmail,

	[Parameter(Mandatory = $false)]
	[string] $OdlConfigName,

	[Parameter (Mandatory = $false)]
	[object] $WebhookData
)



# Generate a random password for Azure AD accounts
function Get-RandomPassword {
	param (
		[Parameter(Mandatory)]
		[ValidateRange(4, [int]::MaxValue)]
		[int] $length,
		[int] $upper = 1,
		[int] $lower = 1,
		[int] $numeric = 1,
		[int] $special = 1
	)

	if ($upper + $lower + $numeric + $special -gt $length) {
		throw "number of upper/lower/numeric/special char must be lower or equal to length"
	}
	$uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	$lCharSet = "abcdefghijklmnopqrstuvwxyz"
	$nCharSet = "0123456789"
	$sCharSet = "#@~"
	$charSet = ""
	if ($upper -gt 0) { $charSet += $uCharSet }
	if ($lower -gt 0) { $charSet += $lCharSet }
	if ($numeric -gt 0) { $charSet += $nCharSet }
	if ($special -gt 0) { $charSet += $sCharSet }
	
	$charSet = $charSet.ToCharArray()
	$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
	$bytes = New-Object byte[]($length)
	$rng.GetBytes($bytes)

	$result = New-Object char[]($length)
	for ($i = 0 ; $i -lt $length ; $i++) {
		$result[$i] = $charSet[$bytes[$i] % $charSet.Length]
	}
	$password = (-join $result)
	$valid = $true
	if ($upper -gt ($password.ToCharArray() | Where-Object { $_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
	if ($lower -gt ($password.ToCharArray() | Where-Object { $_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
	if ($numeric -gt ($password.ToCharArray() | Where-Object { $_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
	if ($special -gt ($password.ToCharArray() | Where-Object { $_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }

	if (!$valid) {
		$password = Get-RandomPassword $length $upper $lower $numeric $special
	}
	return $password
}

function Get-UserTap {
	param (
		[Parameter(Mandatory)]
		[String] $userId,
        [String] $labDuration
	)

	while (!(Get-MgUser -UserId $userId -ErrorAction SilentlyContinue)) {
		Start-Sleep -Seconds 20
	}
	Start-Sleep -Seconds 10
	$startDateTime = (Get-Date).ToUniversalTime()
    $labDurationMinutes = [int]$labDuration * 1440
	$userTap = New-MgUserAuthenticationTemporaryAccessPassMethod -UserId $userId -LifetimeInMinutes $labDurationMinutes -StartDateTime $startDateTime	

	return $userTap.TemporaryAccessPass
}

# Send an Email with user credentials to access the lab
function Send-Email {
	param (
		[Parameter(Mandatory)]
		[String] $toEmail,
		[Parameter(Mandatory)]
		[String] $fromEmail,
		[Parameter(Mandatory)]
		[String] $userNameforEmail,
		[Parameter(Mandatory)]
		[String] $userPswdforEmail,
		[Parameter(Mandatory)]
		[String] $labName,
		[Parameter(Mandatory)]
		[String] $labDuration
	)

	$mailApiKey = Get-AzKeyVaultSecret `
		-VaultName $vaultName `
		-Name "mail-api-key-01" `
		-AsPlainText -DefaultProfile $AzureContext

	$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist "fortinetsecdevops", $(convertto-securestring -Force -AsPlainText $mailApiKey)

	$emailSubject = 'Fortinet Cloud Workshop Information'
	$emailBody = (
		"`nCloud Workshop: $labName has completed provisioning." +
		"`nDuration: $labDuration days." +
		"`n`nAzure Access Credentials" +
		"`nUserName: $userNameforEmail`nPassword: $userPswdforEmail`nPortal: https://portal.azure.com" +
		"`n"
	)

	Send-MailMessage -SmtpServer smtp.gmail.com -Port 587 `
		-UseSsl -From $fromEmail `
		-To $toEmail `
		-Subject $emailSubject -Body $emailBody -Credential $credential -WarningAction SilentlyContinue
}

# Retrieve the On Demand Lab configuration (ODL)
function Get-OdlConfig {
	param (
		[Parameter(Mandatory)]
		[String] $storageBlobUri 
	)

	try {
		$response = Invoke-WebRequest -Uri $storageBlobUri -UseBasicParsing
	}
	catch {
		$_.Exception.Message
		Write-Error "Blob: $storageBlobUri"
		exit
	}
	return $(ConvertFrom-Json -InputObject $response.content)
}

function Get-AvailableUserNameId {
	param (
		[Parameter(Mandatory)]
		[String] $userNamePrefix,
		[Parameter(Mandatory)]
		[array] $userIdNumberRange
	)
	# Get All User IDs with userNamePrefix
    $userIds = Get-MgUser -All -Filter "startsWith(DisplayName, '$($userNamePrefix)')" | Select-Object DisplayName

	# Find first available username in username range
	$availableUserId = 0
	foreach ( $userIdNumber in $userIdNumberRange ) {
		if (("$userNamePrefix$userIdNumber" -notin $userIds.DisplayName)) {

			$availableUserId = $userIdNumber
			break
		}
	}
	return $availableUserId
}

function New-ResourceGroupUserRoleAssignments {
	param (
		[Parameter(Mandatory)]
		[String] $inputResourceGroupName,
		[Parameter(Mandatory)]
		[array] $inputRoleNames,
		[Parameter(Mandatory)]
		[String] $inputUserId
	)

	$userResourceGroupRoleAssignment = Get-AzRoleAssignment -ResourceGroupName $inputResourceGroupName -ObjectId $inputUserId -WarningAction SilentlyContinue
	return $userResourceGroupRoleAssignment
}

###
# No longer needed, Google Analytics is utilized
###
# function Update-StorageTable {
# 	param(
# 		[Parameter(Mandatory = $true)]
# 		[String] $inputResourceGroupName,
# 		[Parameter(Mandatory = $true)]
# 		[String] $inputStorageAccountName,
# 		[Parameter(Mandatory = $true)]
# 		[String] $inputLabName,
# 		[Parameter(Mandatory = $true)]
# 		[array] $inputUserEmail,
# 		[Parameter(Mandatory = $true)]
# 		[array] $inputLabUserId,
# 		[Parameter(Mandatory = $true)]
# 		[array] $inputCustomer,
# 		[Parameter(Mandatory = $true)]
# 		[array] $inputSmartTicket,
# 		[Parameter(Mandatory = $true)]
# 		[array] $inputLabEnvironment
# 	)

#     $cloudTable = Get-AzTableTable -resourceGroup Internal_Training_Automation -TableName workshops -storageAccountName fortinetcloudinttraining

#     $workshopRecords = @()
# 	$workshopRecords = Get-AzTableRow -Table $cloudTable -PartitionKey "workshops" | Where-Object { $_.RowKey.StartsWith($($inputLabName)) }

# 	if ($workshopRecords.Count -eq 0) {
# 		Write-Output "No $($inputLabName) records found"
# 		$nextinstance = 1
# 	}
# 	else {
# 		$instances = @()

# 		foreach ($workshopRecord in $workshopRecords) {
# 			$instance = [int]$workshopRecord.RowKey.Split("-")[1]
# 			$instances += $instance 
# 		}
# 		$sortedInstances = $instances | Sort-Object
# 		$nextInstance = $sortedInstances[$sortedInstances.Count - 1] + 1
# 	}
# 	$nextInstance

# 	Add-AzTableRow -table $cloudTable -partitionKey "workshops" -rowKey ($inputLabName + "-" + $nextInstance) `
# 		-property @{"username" = "$inputUserEmail"; "labUserId" = "$inputLabUserId"; "Customer" = "$inputCustomer"; "SmartTicket" = "$inputSmartTicket"; "Environment" = "$inputLabEnvironment" }
# }

### Main ###

# Running in Azure Automation or locally
if ($env:AUTOMATION_ASSET_ACCOUNTID) {
	Write-OutPut "Running in Azure Automation"
	Clear-AzContext -Force
	Connect-AzAccount -Identity -AccountId a6ecbfa8-081b-470e-9bd1-387971d0939b
    Connect-MgGraph -Identity -ClientId a6ecbfa8-081b-470e-9bd1-387971d0939b

}
else {
	Write-OutPut "Running outside of Azure Automation"
	Connect-AzAccount -SubscriptionName "Internal-Training"
    Connect-MgGraph -Scopes "User.ReadWrite.All","GroupMember.ReadWrite.All","Application.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All" -TenantId (Get-AzContext).Tenant.Id -NoWelcome
}

# If there is WebHook data then extract and use for script operations.
if ($WebhookData) {

	write-output "Header"
	$WebhookData.RequestHeader
	write-output "Body"
	$WebhookData.RequestBody

	if ($WebhookData.RequestBody.StartsWith("{")) {
		$jsonBody = ConvertFrom-Json -InputObject $WebhookData.RequestBody
		$UserOp = $jsonBody.userop
		$UserName = $jsonBody.username
		$OdlConfigName = $jsonBody.odlconfigname
		$UserEmail = $jsonBody.email
		$SmartTicket = $jsonBody.smartTicket
		$Customer = $jsonBody.customer
	}
	else {

		$reqBodyArray = @($WebhookData.RequestBody.Split("&"))
		foreach ($reqBodyItem in $reqBodyArray) {
			if ($reqBodyItem.StartsWith("userop")) {
				$UserOp = $reqBodyItem.Split("=")[1]
			}
			if ($reqBodyItem.StartsWith("useremail")) {
				$tmpUserEmail = $reqBodyItem.Split("=")[1]
				$UserEmail = $tmpUserEmail.Replace("%40", "@")
			}
			if ($reqBodyItem.StartsWith("odlconfigname")) {
				$OdlConfigName = $reqBodyItem.Split("=")[1]
			}
			if ($reqBodyItem.StartsWith("smartticket")) {
				$SmartTicket = $reqBodyItem.Split("=")[1]
			}
			if ($reqBodyItem.StartsWith("customer")) {
				$Customer = $reqBodyItem.Split("=")[1]
			}
		}
		$UserName = ""
	}
}

if ($UserName.Length -eq 0) {
	$UserName = "NA"
}
if ($Customer.Length -eq 0) {
	$Customer = "NA"
}
if ($SmartTicket.Length -eq 0) {
	$SmartTicket = "NA"
}

Write-Output $UserOp, $UserEmail, $OdlConfigName, $UserName, $SmartTicket, $Customer

$vaultName = "internal-training-vault"
$odlConfigUri = Get-AzKeyVaultSecret `
	-VaultName $vaultName `
	-Name "odl-config-uri-tenant-01" `
	-AsPlainText -DefaultProfile $AzureContext

$odlConfig = Get-OdlConfig ($odlConfigUri + $OdlConfigName + ".json")

# What type of lab environment is being used
if ($odlConfig.fortiLabEnv -eq "Azure") {

	# Azure Environment
	# Get the range of available user ID numbers
	$userIdNumberRange = $($odlConfig.userIdNumberRange.Split(":")[0])..($odlConfig.userIdNumberRange.Split(":")[1])

	Write-OutPut "Lab Environment: $($odlConfig.fortiLabEnv)"
	Write-OutPut "Lab Name: $($odlConfig.fortiLabName)"
	Write-OutPut "Restricted: $($odlConfig.fortiRestricted)"
	Write-OutPut "Lab Duration: $($odlConfig.labDuration)"
	Write-OutPut "Number of allowed user accounts: $(($userIdNumberRange).Count)"
	Write-OutPut "Username prefix: $($odlConfig.userNamePrefix)"
	Write-OutPut "User Tenant Domain: $($odlConfig.userTenantDomain)"
	Write-OutPut "User Resource Groups: $($odlConfig.userResourceGroups)"
}
else {

	# Non Azure Environment
	Write-OutPut "Lab Environment: $($odlConfig.fortiLabEnv)"
	Write-OutPut "Lab Name: $($odlConfig.fortiLabName)"
	Write-OutPut "Restricted: $($odlConfig.fortiRestricted)"

    # No longer needed
	# Update-StorageTable "Internal_Training_Automation" `
	# 	"fortinetcloudinttraining" `
	# 	$odlConfig.fortiLabName `
	# 	$UserEmail `
	# 	"NA" `
	# 	$Customer `
	# 	$SmartTicket `
	# 	$odlConfig.fortiLabEnv
	exit
}
if ($UserEmail.StartsWith("test#")) {
	$labDuration = 1
} else {
	$labDuration = $odlConfig.labDuration
}

$userResourceGroupTags = @{FortiLab = "$OdlConfigName"; Duration = "$($labDuration)" }
if ($UserEmail) {
	$userResourceGroupTags.add('Email', $UserEmail)
}

if ($UserOp.Equals("Create")) {

	if ($odlConfig.fortiRestricted.Length -gt 0) {
		if ($UserEmail.Split("@")[1] -in $odlConfig.fortiRestricted) {
			# Restricted lab
			Write-OutPut "$UserEmail is in a valid requestor domain"
		}
		else {
			# Requestor is not a member of a valid domain
			Write-OutPut "$UserEmail is not in a valid requestor domain"
			exit
		}
	}
	else {
		# No restricted lab
		Write-OutPut "Lab is not restricted"
	}

	# Get the user tenant domain
	$tenantDomain = Get-AzKeyVaultSecret `
		-VaultName $vaultName `
		-Name $odlConfig.userTenantDomain `
		-AsPlainText -DefaultProfile $AzureContext

	# Generate a password for the user account
	$userPassword = Get-RandomPassword 12
	
	Write-OutPut "User ID Password: $userPassword"

	# Create the user account - multiple retries if needed due to Azure AD throttling
	# and user ID already in use or not available or multiple simultaneous requests
	# 
	# Retries is the number of allowed user accounts in the lab

	$user = $null
	$userCreationRetries = 0
	While ($userCreationRetries -lt ($userIdNumberRange).Count) {
		$userCreationRetries++
		Write-OutPut "User Creation Attempt: $userCreationRetries"
		$userNameIdNumber = Get-AvailableUserNameId $odlConfig.userNamePrefix $userIdNumberRange
		if ($userNameIdNumber -gt 0) {
			Start-Sleep -Seconds (($userIdNumberRange).Count % 2)
			$userNameLogin = "$($odlConfig.userNamePrefix)$userNameIdNumber"
			$userPrincipal = "$userNameLogin@$tenantDomain"
	
			$user = New-AzADUser `
				-DisplayName  $userNameLogin `
				-MailNickname  $userNameLogin `
				-UserPrincipalName $userPrincipal `
				-Password $(convertto-securestring -Force -AsPlainText $userPassword) `
				-ErrorAction SilentlyContinue `
			
			if ($user) {
                Start-Sleep -Seconds 10
				$userTap = Get-UserTap $($user.UserPrincipalName) $labDuration
				Write-Output "User TAP: $userTap"
				Write-OutPut "User ID available slot found: $userNameIdNumber"
				Write-OutPut "User ID created user: $userNameLogin"
				Write-OutPut "User Principal: $($user.UserPrincipalName)"
				$userResourceGroupTags.add('UserPrincipalName', $user.UserPrincipalName)

				break
			}
			else {
				Write-OutPut "User ID creation failed: $userNameIdNumber"
				$userNameIdNumber = 0
			}
		}
	}

	if ($userNameIdNumber -gt 0) {
		if ($user) {
            # No longer needed
			# if ($UserEmail.StartsWith("test#")) {
			# 	$UserEmail = $UserEmail.Split("#")[1]
			# } else {
			# 	Update-StorageTable "Internal_Training_Automation" `
			# 		"fortinetcloudinttraining" `
			# 		$odlConfig.fortiLabName `
			# 		$UserEmail `
			# 		$user.UserPrincipalName `
			# 		$Customer `
			# 		$SmartTicket `
			# 		$odlConfig.fortiLabEnv
			# }
			foreach ($userResourceGroup in $odlConfig.userResourceGroups) {
				$resourceGroupname = "$($user.displayName)-$($userResourceGroup.suffix)"
				$resourceGroupLocation = $userResourceGroup.location

				$resourceGroup = Get-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation -ErrorAction SilentlyContinue
				
				if ($resourceGroup) {

					Write-OutPut "User Resource Group already exists: $resourceGroupname"
					$userResourceGroupRoleAssignment = Get-AzRoleAssignment -ResourceGroupName $resourceGroupname -ObjectId $user.Id -WarningAction SilentlyContinue

					if (!$userResourceGroupRoleAssignment) {
						$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
						$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName "User Access Administrator" -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
					}
				}
				else {

					Write-OutPut "User Resource Group creating: $resourceGroupname"
					$resourceGroup = New-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation -Tag $userResourceGroupTags
					$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Contributor" -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
					$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName "User Access Administrator" -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
				}

				if ($userResourceGroup.storage) {

					$randomString = ([char[]]([char]'a'..[char]'z') + 0..9 | Sort-Object { get-random })[0..11] -join ''

					Write-OutPut "User Resource Group storage creating: $($user.displayName)$randomString"
					$storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name "$($user.displayName)$randomString" -SkuName Standard_LRS  -WarningAction SilentlyContinue

					if ($storageAccount) {

						Start-Sleep -Seconds 20

						Write-OutPut "User Resource Group storage created: $($user.displayName)$randomString"
						Write-OutPut "User Resource Group storage fileshare creating: $($user.displayName)$randomString"
						$storageAccountShare = $storageAccount | New-AzStorageShare -Name $userResourceGroup.sharename -WarningAction SilentlyContinue
					}
				}

				if ($userResourceGroup.bastion) {

					$publicIpAddress = New-AzPublicIpAddress -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name pip-bastion -AllocationMethod Static -Sku Standard

					Write-OutPut "User Virtual Network creating: $userResourceGroup.utilityVnetName"
					$vnet = New-AzVirtualNetwork -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name $userResourceGroup.utilityVnetName -AddressPrefix $userResourceGroup.utilityVnetCIDR -WarningAction SilentlyContinue

					if ($vnet) {
						$bastionSubnet = Add-AzVirtualNetworkSubnetConfig -Name $userResourceGroup.bastionSubnetName -VirtualNetwork $vnet -AddressPrefix $userResourceGroup.bastionSubnetPrefix  -WarningAction SilentlyContinue
						$utilitySubnet = Add-AzVirtualNetworkSubnetConfig -Name $userResourceGroup.utilitySubnetName -VirtualNetwork $vnet -AddressPrefix $userResourceGroup.utilitySubnetPrefix  -WarningAction SilentlyContinue

						$vnetWithSubnets = $vnet | Set-AzVirtualNetwork
					}

					$nicIpConfig = New-AzNetworkInterfaceIpConfig -SubnetId "$($vnetWithSubnets.Id)/subnets/utility" -Name ipconfig1
					$nic = New-AzNetworkInterface -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name nic-vm-linux -IpConfiguration $nicIpConfig

					Write-OutPut "User Bastion Host creating: bastion"
					New-AzBastion -ResourceGroupName $resourceGroupname -Name "bastion" `
						-PublicIpAddressRgName $resourceGroupname -PublicIpAddressName $publicIpAddress.Name `
						-VirtualNetworkRgName $resourceGroupname -VirtualNetworkName $vnet.Name `
						-Sku "Standard"

					$VmName = "vm-linux-$($user.displayName)"
					$VmUsername = $($user.displayName)
					$VmPassword = ConvertTo-SecureString '123Password#@!' -AsPlainText -Force
					$Credential = New-Object System.Management.Automation.PSCredential ($VmUsername, $VmPassword)

					$VirtualMachine = New-AzVMConfig -VMName $VmName -VMSize "Standard_D2_v3"
					$VirtualMachine = Set-AzVMOperatingSystem -Linux -VM $VirtualMachine -ComputerName $VmName -Credential $Credential
					$VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $nic.Id
					$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'Canonical' -Offer 'UbuntuServer' -Skus '18.04-LTS' -Version latest
					$VirtualMachine = Set-AzVMBootDiagnostic -VM $VirtualMachine -Enable -ResourceGroupName $resourceGroupname -StorageAccountName "$($user.displayName)$randomString"

					New-AzVM -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -VM $VirtualMachine -Verbose
				}
			}
		}

		# Everything is created send an email with login credentials
		Write-Output "Sending email: $UserEmail fortinetsecdevops@gmail.com $($user.userPrincipalName)  $userTap $($odlConfig.fortiLabName) $($odlConfig.labDuration)"
		Send-Email $UserEmail fortinetsecdevops@gmail.com $($user.userPrincipalName)  $userTap $($odlConfig.fortiLabName) $($odlConfig.labDuration)
	}
	else {
		# No available lab slots
		Write-OutPut "No User IDs Available"
	}
}

if ($UserOp.Equals("List")) {
    $userIds = Get-MgUser -All -Filter "startsWith(DisplayName, '$($odlConfig.userNamePrefix)')" | Select-Object DisplayName
	$usedIds
}

if ($UserOp.Equals("Delete")) {

	# Remove User Account
    $userAccount = Get-MgUser -All -Filter "startsWith(UserPrincipalName, '$($UserName)')"
	if ($userAccount) {
		Remove-AzADUser	 -DisplayName $UserName
		Write-OutPut "User ID deleted: $UserName"
	}
	else {
		Write-OutPut "User ID not found: $UserName"
	}

	# Remove User Resource Groups
	foreach ($userResourceGroup in $odlConfig.userResourceGroups) {

		$resourceGroupname = "$UserName-$($userResourceGroup.suffix)"
		$resourceGroupLocation = $userResourceGroup.location

		$resourceGroup = Get-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation -ErrorAction SilentlyContinue
		
		if ($resourceGroup) {

			$removeUserResourceGroup = Remove-AzResourceGroup -Id $resourceGroup.ResourceId -Force
			Write-OutPut "User Resource Group found, deleting: $resourceGroupname"
			Write-Output $removeUserResourceGroup

		}
		else {
			Write-OutPut "User Resource Group not found: $resourceGroupname"
		}
	}
}

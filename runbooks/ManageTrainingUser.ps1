<#
    .DESCRIPTION
        Manage Azure AD Training Users and On Demand Labs

    .NOTES
        AUTHOR: jmcdonough@fortinet.com
        LASTEDIT: Feb 07, 2024
#>

# Can be run via WebHook or from Cmd line.
param(
	[CmdletBinding()]
	[Parameter(Mandatory = $false)]
	[ValidateSet("Create", "Delete", "List", "Email")]
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

# Gernerate a random password for Azure AD accounts
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

# Send and Email with user credentails to access the lab
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

	$emailSubject = 'Fortinet Azure TEC Workshop Information'
	$emailBody = (
		"`nTEC Workshop: $labName has completed provisioning." +
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

# Retrieve the On Demand Lab configuration
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

	Write-Output $response
	$odlConfiguration = ConvertFrom-Json -InputObject $response.content

	$odlConfigHash = @{
		fortiLabName       = $odlConfiguration.fortiLabName;
		labDuration        = $odlConfiguration.labDuration;
		userResourceGroups = $odlConfiguration.userResourceGroups;
		userIdNumberRange  = ($odlConfiguration.userIdNumberRange.Split(":")[0])..($odlConfiguration.userIdNumberRange.Split(":")[1]);
		userNamePrefix     = $odlConfiguration.userNamePrefix;
		userTenantDomain   = $odlConfiguration.userTenantDomain
	}

	return $odlConfigHash
}

function Get-AvailableUserNameId {
	param (
		[Parameter(Mandatory)]
		[String] $userNamePrefix,
		[Parameter(Mandatory)]
		[array] $userIdNumberRange
	)
	# Get All User IDs with username prefix
	$userdIds = Get-AzADUser -StartsWith $userNamePrefix | Select-Object DisplayName

	# Find first available username in username range
	$availableUserId = 0
	foreach ( $userIdNumber in $userIdNumberRange ) {
		if (("$userNamePrefix$userIdNumber" -notin $userdIds.DisplayName)) {

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
}

function Update-StorageTable{
  param(
      [Parameter(Mandatory=$true)]
      [String] $inputResourceGroupName,
      [Parameter(Mandatory=$true)]
      [String] $inputStorageAccountName,
      [Parameter(Mandatory=$true)]
      [String] $inputLabName,
      [Parameter(Mandatory=$true)]
      [array] $inputUserEmail,
      [Parameter(Mandatory=$true)]
      [array] $inputLabUserId,
      [Parameter(Mandatory=$true)]
      [array] $inputCustomer,
      [Parameter(Mandatory=$true)]
      [array] $inputSmartTicket
  )

  $storageAccount = Get-AzStorageAccount -ResourceGroupName $inputResourceGroupName -Name $inputStorageAccountName
  $storageTable = Get-AzStorageTable –Name "workshops" –Context $storageAccount.Context

  $workshopRecords = Get-AzTableRow -table $storageTable.CloudTable | Where-Object {$_.RowKey.StartsWith($inputLabName)}

  if ($workshopRecords.Count -eq 0) {
      Write-Output "No $($inputLabName) records found"
      $nextinstance = 1
  }
  else {
      $instances = @()
  
      foreach ($workshopRecord in $workshopRecords) {
          $instance = [int]$workshopRecord.RowKey.Split("-")[1]
          $instances += $instance 
      }
      $sortedInstances = $instances | Sort-Object
      $nextInstance = $sortedInstances[$sortedInstances.Count-1] + 1
  }
  $nextInstance

  Add-AzTableRow -table $storageTable.CloudTable -partitionKey "workshops" -rowKey ($inputLabName+"-"+$nextInstance) `
	  -property @{"username"="$inputUserEmail";"labUserId"="$inputLabUserId";"Customer"="$inputCustomer";"SmartTicket"="$inputSmartTicket"}
}

### Main ###

Import-Module AzTable

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

if ($Customer.Length -eq 0) {
	$Customer = "NA"
}
if ($SmartTicket.Length -eq 0) {
	$SmartTicket = "NA"
}

Write-Output $UserOp, $UserEmail, $OdlConfigName, $UserName, $SmartTicket, $Customer
$vaultName = "internal-training-vault"

if ($env:AUTOMATION_ASSET_ACCOUNTID) {
	Write-OutPut "Running in Azure Automation"
	Clear-AzContext -Force
	Connect-AzAccount -Identity

}
else {
	Write-OutPut "Running outside of Azure Automation"
	Connect-AzAccount -SubscriptionName "Internal-Training"
}

$odlConfigUri = Get-AzKeyVaultSecret `
	-VaultName $vaultName `
	-Name "odl-config-uri-tenant-01" `
	-AsPlainText -DefaultProfile $AzureContext

$odlConfig = Get-OdlConfig ($odlConfigUri + $OdlConfigName + ".json")

Write-OutPut "User Resource Groups: $($odlConfig.userResourceGroups)"
Write-OutPut "Number of allowed user accounts: $(($odlConfig.userIdNumberRange).Count)"
Write-OutPut "Username prefix: $($odlConfig.userNamePrefix)"
Write-OutPut "User Tenant Domain: $($odlConfig.userTenantDomain)"
Write-OutPut "Lab Name: $($odlConfig.fortiLabName)"
Write-OutPut "Lab Duration: $($odlConfig.labDuration)"

$userResourceGroupTags = @{FortiLab = "$OdlConfigName"; Duration = "$($odlConfig.labDuration)" }
if ($UserEmail) {
	$userResourceGroupTags.add('Email', $UserEmail)
}

if ($UserOp.Equals("Create") -and ($UserEmail.EndsWith("fortinet.com") -or $UserEmail.EndsWith("fortinet-us.com"))) {

	# Get available UserID #, combining an available ID number in the userIdNumberRange with userNamePrefix
	$userNameIdNumber = Get-AvailableUserNameId $odlConfig.userNamePrefix $odlConfig.userIdNumberRange

	# Create a user Login with the found available user ID Number and userNamePrefix
	$tenantDomain = Get-AzKeyVaultSecret `
		-VaultName $vaultName `
		-Name $odlConfig.userTenantDomain `
		-AsPlainText -DefaultProfile $AzureContext

	if ($userNameIdNumber -gt 0) {
		$userNameLogin = "$($odlConfig.userNamePrefix)$userNameIdNumber"
		$userPrincipal = "$userNameLogin@$tenantDomain"

		Write-OutPut "User ID available slot found: $userNameIdNumber"
		Write-OutPut "User ID creating user: $userNameLogin"
		Write-OutPut "User Principal: $userPrincipal"

		$userPassword = Get-RandomPassword 12
		Write-OutPut "User ID Password: $userPassword"

		$user = New-AzADUser `
			-DisplayName  $userNameLogin `
			-MailNickname  $userNameLogin `
			-UserPrincipalName $userPrincipal `
			-Password $(convertto-securestring -Force -AsPlainText $userPassword) `
			-ErrorAction Stop
		
		Write-OutPut "User ID created user: $user"

		$userResourceGroupTags.add('UserPrincipalName', $user.UserPrincipalName)

		if ($user) {

      Update-StorageTable "Internal_Training_Automation" "fortinetcloudinttraining" $odlConfig.fortiLabName $UserEmail $user.UserPrincipalName $Customer $SmartTicket

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
		Send-Email $UserEmail fortinetsecdevops@gmail.com $($user.userPrincipalName)  $userPassword $($odlConfig.fortiLabName) $($odlConfig.labDuration)
	}
	else {
		# No available lab slots
		Write-OutPut "No User IDs Available"
	}
}
else {
	if ($UserOp.Equals("Create")) {
		# Requestor is not a mmber of a valid domain
		Write-OutPut "$UserEmail is not a valid requestor domain"
	}
}

if ($UserOp.Equals("List")) {
	$usedIds = Get-AzADUser -StartsWith $odlConfig.userNamePrefix | Select-Object DisplayName
	$usedIds
}

if ($UserOp.Equals("Delete")) {

	# Remove User Account
	$userAccount = Get-AzADUser -DisplayName $UserName
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

<#
    .DESCRIPTION
        Manage Azure AD Training Users and On Demand Labs

    .NOTES
        AUTHOR: jmcdonough@fortinet.com
        LASTEDIT: Aug 31, 2022
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Create","Delete", "List")]
    [string] $UserOp,

    [Parameter(Mandatory = $false)]
    [string] $UserName,

    [Parameter(Mandatory = $false)]
    [string] $OdlConfig,

		[Parameter (Mandatory = $false)]
    [object] $WebhookData
)

if ($WebhookData) {

    write-output "Header"
    $WebhookData.RequestHeader
    write-output "Body"
    $WebhookData.RequestBody

    $jsonBody = ConvertFrom-Json -InputObject $WebhookData.RequestBody

    $UserOp = $jsonBody.userop
    $UserName = $jsonBody.username
		$OdlConfig = $jsonBody.odlconfig

    Write-Output $UserOp,$UserName,$OdlConfig
}

if ($env:AUTOMATION_ASSET_ACCOUNTID) {
	"Running in Azure Automation"
	Clear-AzContext -Force
	Connect-AzAccount -Identity

} else {
	"Running outside of Azure Automation"
}

$storageBlobUri = "https://fortinetcloudinttraining.blob.core.windows.net/fortinetcloudtraining-labconfigurations/" + $OdlConfig + ".json"
$response = Invoke-WebRequest -Uri $storageBlobUri -UseBasicParsing
$odlConfiguration = ConvertFrom-Json -InputObject $response.content

$userResourceGroups = $odlConfiguration.userResourceGroups
$userIdNumberRange  = ($odlConfiguration.userIdNumberRange.Split(":")[0])..($odlConfiguration.userIdNumberRange.Split(":")[1])
$userNamePrefix     = $odlConfiguration.userNamePrefix
$userTenantDomain   = $odlConfiguration.userTenantDomain
$userPassword       = $odlConfiguration.userPassword

if ($UserOp.Equals("Create")) {

	# Get All User IDs with username prefix
	$usedIds = Get-AzADUser -StartsWith $userNamePrefix | Select-Object DisplayName

	# Find first available username in username range
	$avaiableUserId = $false
	foreach ( $userIdNumber in $userIdNumberRange ) {
		if (("$userNamePrefix$userIdNumber" -notin $usedIds.DisplayName)) {

			$avaiableUserId = $true
			Write-OutPut "User ID available slot found: $userIdNumber"

			Write-OutPut "User ID creating user: $userNamePrefix$userIdNumber"
			$user = New-AzADUser `
				-DisplayName $userNamePrefix$userIdNumber `
				-MailNickname $userNamePrefix$userIdNumber `
				-UserPrincipalName $userNamePrefix$userIdNumber@$userTenantDomain `
				-Password $(convertto-securestring -Force -AsPlainText $userPassword)
			
			Write-OutPut "User ID created user: $user"

			foreach ($userResourceGroup in $userResourceGroups.GetEnumerator()) {
				$resourceGroupname = "$($user.displayName)-$($userResourceGroup.suffix)"
				$resourceGroupLocation = $userResourceGroup.location

				$resourceGroup = Get-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation -ErrorAction SilentlyContinue
				
				if ($resourceGroup) {

					Write-OutPut "User Resource Group already exists: $resourceGroupname"
					$userResourceGroupRoleAssignment = Get-AzRoleAssignment -ResourceGroupName $resourceGroupname -ObjectId $user.Id -WarningAction SilentlyContinue

					if (!$userResourceGroupRoleAssignment) {
						$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName Contributor -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
					}

				} else {

					Write-OutPut "User Resource Group creating: $resourceGroupname"
					$resourceGroup = New-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation
					$newUserResourceGroupRoleAssignment = New-AzRoleAssignment -RoleDefinitionName Contributor -ObjectId $user.Id -Scope $resourceGroup.ResourceId -WarningAction SilentlyContinue
				}

				if ($userResourceGroup.storage) {

					$randomString = ([char[]]([char]'a'..[char]'z') + 0..9 | Sort-Object {get-random})[0..11] -join ''

					Write-OutPut "User Resource Group storage creating: $($user.displayName)$randomString"
					$storageAccount = New-AzStorageAccount -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name "$($user.displayName)$randomString" -SkuName Standard_LRS  -WarningAction SilentlyContinue

					if ($storageAccount) {

						Write-OutPut "User Resource Group storage created: $($user.displayName)$randomString"
						Write-OutPut "User Resource Group storage fileshare creating: $($user.displayName)$randomString"
						$storageAccountShare = $storageAccount | New-AzStorageShare -Name $userResourceGroup.sharename -WarningAction SilentlyContinue
					}
				}

				if ($userResourceGroup.bastion) {

					Write-OutPut "User Virtual Network creating: $($user.displayName)$randomString"
					$vnet = New-AzVirtualNetwork -ResourceGroupName $resourceGroupname -Location $resourceGroupLocation -Name $userResourceGroup.utilityVnetName -AddressPrefix $userResourceGroup.utilityVnetCIDR -WarningAction SilentlyContinue

					if ($vnet) {
						$bastionSubnet = Add-AzVirtualNetworkSubnetConfig -Name $userResourceGroup.bastionSubnetName -VirtualNetwork $vnet -AddressPrefix $userResourceGroup.bastionSubnetPrefix  -WarningAction SilentlyContinue
						$utilitySubnet = Add-AzVirtualNetworkSubnetConfig -Name $userResourceGroup.utilitySubnetName -VirtualNetwork $vnet -AddressPrefix $userResourceGroup.utilitySubnetPrefix  -WarningAction SilentlyContinue
						$vnetwithSubnets = $vnet | Set-AzVirtualNetwork
					}
				}
			}
			break
		}
	}

	if ($avaiableUserId -eq $false) {
		Write-OutPut "User IDs unavailable"
	}
}

if ($UserOp.Equals("List")) {

	$usedIds = Get-AzADUser -StartsWith $userNamePrefix | Select-Object DisplayName
	$usedIds
}

if ($UserOp.Equals("Delete")) {

	# Remove User Account
	$userAccount = Get-AzADUser -DisplayName $UserName
	if ($userAccount) {
		Remove-AzADUser	 -DisplayName $UserName
		Write-OutPut "User ID deleted: $UserName"
	} else {
		Write-OutPut "User ID not found: $UserName"
	}

	# Remove User Resource Groups
	foreach ($userResourceGroup in $userResourceGroups.GetEnumerator()) {

		$resourceGroupname = "$UserName-$($userResourceGroup.suffix)"
		$resourceGroupLocation = $userResourceGroup.location

		$resourceGroup = Get-AzResourceGroup -Name $resourceGroupname -Location $resourceGroupLocation
		
		if ($resourceGroup) {

			$removeUserResourceGroup = Remove-AzResourceGroup -Id $resourceGroup.ResourceId -Force
			Write-OutPut "User Resource Group found, deleting: $resourceGroupname"

		} else {
			Write-OutPut "User Resource Group not found: $resourceGroupname"
		}
	}
}

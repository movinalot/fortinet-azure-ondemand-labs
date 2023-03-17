<#
    .DESCRIPTION
        Manage Azure AD Training User On Demand Lab Environments

    .NOTES
        AUTHOR: jmcdonough@fortinet.com
        LASTEDIT: Jan 26, 2023
#>

### Main ###

if ($env:AUTOMATION_ASSET_ACCOUNTID) {
	Write-OutPut "Running in Azure Automation"
	Clear-AzContext -Force
	Connect-AzAccount -Identity

}
else {
	Write-OutPut "Running outside of Azure Automation"
	Connect-AzAccount -SubscriptionName "Internal-Training" -WarningAction SilentlyContinue
}

$resourceGroups = Get-AzResourceGroup

foreach ($resourceGroup in $resourceGroups) {

		$resourceGroupTagKeys = $resourceGroup.Tags.Keys
		if ("CreatedOnDate" -in $resourceGroupTagKeys -and "FortiLab" -in $resourceGroupTagKeys -and "Duration" -in $resourceGroupTagKeys) { 
	
			$rgCreatedOnDate = [datetime]$resourceGroup.Tags["CreatedOnDate"]

			$rightNow = Get-Date 

			$totalDays = ($rightNow - $rgCreatedOnDate).TotalDays
			$totalDaysString = $totalDays.ToString("##.##")

			Write-Output "Resource Group: $($resourceGroup.ResourceGroupName)"
			if ($totalDays -gt $resourceGroup.Tags["Duration"]) {
				Write-Output "Reservation time exceeded  - Running time: $totalDaysString - Expected duration: $($resourceGroup.Tags["Duration"])"
				$removeResourceGroup = Remove-AzResourceGroup -Id $resourceGroup.ResourceId -Force

				if ($removeResourceGroup) {
					Write-OutPut "Removed Resource Group: $($resourceGroup.ResourceGroupName)"
				}
			} else {
				Write-Output "Reservation time remaining - Running time: $totalDaysString - Expected duration: $($resourceGroup.Tags["Duration"])"
				Write-Output "UserPrincipalName: $($resourceGroup.Tags["UserPrincipalName"])"
				Write-Output "Email: $($resourceGroup.Tags["Email"])"
				Write-Output "FortiLab: $($resourceGroup.Tags["FortiLab"])"
				./ManageTrainingUser.ps1 -UserOp List -OdlConfigName sdwan-lab
			}
		}
}
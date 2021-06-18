try {
    $groupName = $datasource.selectedGroup.name     
    Write-information "Searching AD group [$groupName]"

    $adGroup = Get-ADgroup -Filter {Name -eq $groupName} -Properties Name, Description | Select-Object Name, Description
    Write-information "Finished searching AD group [$groupName]"
         
    foreach($tmp in $adGroup.psObject.properties)
    {
        $returnObject = @{name=$tmp.Name; value=$tmp.value}
        Write-Output $returnObject
    }
     
    Write-Information "Finished retrieving AD  group [$groupName] basic attributes"
} catch {
    Write-Error "Error retrieving AD  group [$groupName] basic attributes. Error: $($_.Exception.Message)"
}

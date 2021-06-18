try {
    $groupName = $datasource.selectedGroup.name     
    Write-information "Searching AD group [$groupName]"
     
    if([String]::IsNullOrEmpty($groupName) -eq $true){
        return
    } else {
        $adGroup = Get-ADgroup -Filter {Name -eq $groupName} -Properties Members
        Write-information "Finished searching AD group [$groupName]"
         
        $users = Get-ADGroupMember $adGroup | Select-Object name, sid | Sort-Object name
        $users = $users
        $resultCount = @($users).Count
         
        # Write-Information "Groupmemberships: $resultCount"
         
        if($resultCount -gt 0) {
            foreach($user in $users)
            {
                $returnObject = @{name="$($user.name)"; sid = [string]"$($user.sid)"}
                Write-Output $returnObject
            }
        }
    }
} catch {
    Write-Error "Error getting members [$groupName]. Error: $($_.Exception.Message)"
}

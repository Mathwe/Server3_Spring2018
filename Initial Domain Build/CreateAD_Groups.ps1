#import Active Directory Module
Import-Module ActiveDirectory

#Assign the contents of the ImportOUs.csv to the variable $csv using the import-csv cmdlet
$GROUPS= import-csv "C:\PS-Scripting\Initial Domain Build\ImportGroups.csv"

#begin foreach loop. $GROUP is each row in the $GROUP file. The header of each column is represented in the $GROUP.xxx within New-ADOrganizationalUnit parameter
foreach ($GROUP in $GROUPS){
	New-ADGroup -Name $GROUP.Name -GroupCategory $GROUP.GroupCategory -GroupScope $GROUP.GroupScope -Path $GROUP.Path -Verbose
	#Remove-adgroup -Identity $GROUP.Name
}
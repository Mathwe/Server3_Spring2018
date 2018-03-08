#import Active Directory Module
Import-Module ActiveDirectory

#Assign the contents of the ImportOUs.csv to the variable $csv using the import-csv cmdlet
$OUS= import-csv "C:\PS-Scripting\Initial Domain Build\ImportOUs.csv"

#begin foreach loop. $OU is each row in the $OU file. The header of each column is represented in the $OU.xxx within New-ADOrganizationalUnit parameter
foreach ($OU in $OUS){
	New-ADOrganizationalUnit -Name $OU.Name -Description $OU.Description -DisplayName $OU.DisplayName -Path $OU.Path -ProtectedFromAccidentalDeletion $False -verbose
}
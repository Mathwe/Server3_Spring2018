#import Active Directory Module
Import-Module ActiveDirectory

#Assign the contents of the ImportUsers.csv to the variabl $ucsv using the import-csv cmdlet
$users=import-csv "C:\PS-Scripting\Initial Domain Build\ImportUsers.csv"

#begin foreach loop. $user is each row in the $ucsv file. The header of each column is represented in the $user.xxx within New-ADUser parameter
foreach ($user in $users){ 
    $isPresent=$null
    $isPresent=get-aduser -Filter "SamAccountName -eq '$($user.samAccountName)'"

    $userName=$user.name.split(' ')
    $userNameFirstU=$userName[0].Substring(0,1).toUpper()+$userName[0].Substring(1).tolower()
    $userNameFirstL=$userName[0].Substring(0).toLower()
    $userNameLastU=$userName[1].Substring(0,1).toUpper()+$userName[0].Substring(1).tolower()
    $userNameLastL=$userName[1].Substring(0).tolower()
    $user.name="$userNameFirstU $userNameLastU"
    $user.SamAccountName="$userNameFirstU.$userNameLastL"
    $user.Department=$user.Department.Substring(0,1).toUpper()+$user.Department.Substring(1).tolower()

    if ($isPresent -eq $null) {
        Write-output "User doesn't exist, Creating" | Write-Host
        New-ADUser -Name $user.Name -SamAccountName $user.SamAccountName -Department $user.Department -Path $user.Path -OfficePhone $user.OfficePhone -AccountPassword (ConvertTo-SecureString $user.AccountPassword -AsPlainText -force) -verbose
        Add-ADGroupMember -Members $user.SamAccountName -Identity $user.department -verbose
    }
    else {
        Write-Output "User does exist, modifying" | Write-Host

    }


    #New-ADUser -Name $user.Name -SamAccountName $user.SamAccountName -Department $user.Department -Path $user.Path -OfficePhone $user.OfficePhone -AccountPassword (ConvertTo-SecureString $user.AccountPassword -AsPlainText -force) -verbose

}

#Finish up! You have to add the groups before you can add them users to them.
#Add users to their department's security group
#ADD-ADGroupMember “InfoTech_Group” –members “James.Kirk","Sam.Malone","Ryan.Howard","Daryll.Philbin"
#ADD-ADGroupMember “Accounting_Group” –members “Angela.Martin","Kevin.Malone","Oscar.Martinez","Cosmo.Kramer"
#ADD-ADGroupMember “Developers_Group” –members “Peter.Gibbons","Michael.Bolton","Tom.Smykowski","Bill.Lumbergh"
#ADD-ADGroupMember “Manufacturing_Group” –members “Michael.Scott","Milton.Waddams","Bob.Slydell","Bob.Porter"
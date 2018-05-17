#import Active Directory Module
Import-Module ActiveDirectory

#Assign the contents of the ImportUsers.csv to the variabl $ucsv using the import-csv cmdlet
$users=import-csv ".\ImportUsers.csv"

#begin foreach loop. $user is each row in the $ucsv file. The header of each column is represented in the $user.xxx within New-ADUser parameter
foreach ($user in $users){ 
    $isPresent=$null
    $isPresent=get-aduser -Filter "SamAccountName -eq '$($user.samAccountName)'"

    $userName=$user.name.split(' ')
    $userNameFirstU=$userName[0].Substring(0,1).toUpper()+$userName[0].Substring(1).tolower()
    $userNameFirstL=$userName[0].Substring(0).toLower()
    $userNameLastU=$userName[1].Substring(0,1).toUpper()+$userName[1].Substring(1).tolower()
    $userNameLastL=$userName[1].Substring(0).tolower()
    $user.name = @()
    $user.name += $userName[0]
    $user.name += $userName[1]
    $user.name += "$userNameFirstU $userNameLastU"
    $user.SamAccountName="$userNameFirstL.$userNameLastL"
    $user.Department=$user.Department.Substring(0,1).toUpper()+$user.Department.Substring(1).tolower()

    if ($isPresent -eq $null) {
        Write-output "User doesn't exist, Creating" | Write-Host
        New-ADUser -Name $user.Name[2] -SamAccountName $user.SamAccountName -Department $user.Department -Path $user.Path -OfficePhone $user.OfficePhone -AccountPassword (ConvertTo-SecureString $user.AccountPassword -AsPlainText -force) -verbose
        Add-ADGroupMember -Members $user.SamAccountName -Identity "$($user.department)_Group" -verbose
    }
    else {
        Write-Output "User does exist, modifying" | Write-Host
        Set-Aduser -Identity $user.SamAccountName -GivenName $user.name[0] -Surname $user.name[1] -SamAccountName $user.SamAccountName -Department $user.Department -OfficePhone $user.OfficePhone -Verbose
        Add-ADGroupMember -Members $user.SamAccountName -Identity "$($user.Department)_Group" -Verbose


    }


    #New-ADUser -Name $user.Name -SamAccountName $user.SamAccountName -Department $user.Department -Path $user.Path -OfficePhone $user.OfficePhone -AccountPassword (ConvertTo-SecureString $user.AccountPassword -AsPlainText -force) -verbose

}

#Finish up! You have to add the groups before you can add them users to them.
#Add users to their department's security group
#ADD-ADGroupMember “InfoTech_Group” –members “James.Kirk","Sam.Malone","Ryan.Howard","Daryll.Philbin"
#ADD-ADGroupMember “Accounting_Group” –members “Angela.Martin","Kevin.Malone","Oscar.Martinez","Cosmo.Kramer"
#ADD-ADGroupMember “Developers_Group” –members “Peter.Gibbons","Michael.Bolton","Tom.Smykowski","Bill.Lumbergh"
#ADD-ADGroupMember “Manufacturing_Group” –members “Michael.Scott","Milton.Waddams","Bob.Slydell","Bob.Porter"
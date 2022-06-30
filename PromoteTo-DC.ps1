<#
.SYNOPSIS
   This script promotes a server to a domain controller.
.DESCRIPTION
   This script promotes a server to a domain controller by installing the ADDS role if needed, joining the domain, installing DNS, and promoting the computer to a DC. 
.EXAMPLE
   PS:> PromoteTo-DC.ps1
   Prompts for required parameters DomainName, SafemodePW, and Credential (for domain join). Uses default values for any other settings.
.EXAMPLE
   PS:> PromoteTo-DC.ps1 -DomainName 'Example.com' -SafemodePW (v3ryS3cure! | ConvertTo-SecureString -AsPlainText -Force) -Credential (Get-Credential) -DBPath d:\ADdb -LogPath 'L:\ADlog' -SysvolPath S:\Sysvol
   Full control of installation using parameters instead of prompts.
.EXAMPLE
   PS:> $Cred = get-credential somedomain\DomaiAdminUseName ; $SafemodePW = read-host "Safe Mode PW" -AsSecureString
   PS:> PromoteTo-DC.ps1 -DomainName 'Example.com' -SafemodePW $SafemodePW -Credential $Cred -DBPath d:\ADdb -LogPath 'L:\ADlog' -SysvolPath S:\Sysvol
   Full control of installation using parameters instead of prompts. Pre-populate credential and safemodepw so they are not displayed as plain text.
.NOTES
   Chad R. Smith, 6/2/2022
#>
#Requires -RunasAdministrator 

[CmdletBinding()] 
Param(
    # Domain in which DC will be promoted. 
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)][String]$DomainName,
    # Safe mode administrtor password (recommend different PW for each DC). 
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=1)][SecureString]$SafemodePW,
    # User credential for adding DC. Should be a domain admin. 
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][System.Management.Automation.PSCredential]$Credential,    
    # Path to AD DB. 
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$DBPath,
    # Path to AD log. 
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$LogPath,
    # Path to sysvol. 
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][String]$SysvolPath,
    # Install DNS. 
    [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$true)][Switch]$InstallDns = $true
)

Write-verbose 'Check for and install AD role.'
If( (Get-WindowsFeature AD-Domain-Services).InstallState -ne 'Installed' ){
    Install-WindowsFeature Ad-Domain-Services -IncludeAllSubFeature -IncludeManagementTools -Restart
}

Write-Verbose 'Set up Install-ADDSDomainController splat according to entered params'
$ADDCSplat = @{
DomainName = $Domainname
SafeModeAdministratorPassword = ( ConvertTo-SecureString -AsPlainText $SafemodePw -Force )
Credential = $Credential
}
If( $DBPath ){ $ADDCSplat.add('DatabasePath',$DBPath) }
If( $LogPath ){ $ADDCSplat.add('LogPath',$LogPath) }
If( $SysvolPath ){ $ADDCSplat.Add('SysvolPath',$SysvolPath) }
If( $InstallDns ){ $ADDCSplat.Add('InstallDns',$true) }

#$ADDCSplat
Install-ADDSDomainController @ADDCSplat

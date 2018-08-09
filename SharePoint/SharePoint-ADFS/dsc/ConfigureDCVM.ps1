configuration ConfigureDCVM
{
    param
    (
        [Parameter(Mandatory)] [String]$DomainFQDN,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$Admincreds,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$AdfsSvcCreds,
        [Parameter(Mandatory)] [String]$PrivateIP
    )

    Import-DscResource -ModuleName xActiveDirectory, xNetworking, xPSDesiredStateConfiguration, ActiveDirectoryCSDsc, CertificateDsc, xPendingReboot, cADFS, xDnsServer
    [String] $DomainNetbiosName = (Get-NetBIOSName -DomainFQDN $DomainFQDN)
    [System.Management.Automation.PSCredential] $DomainCredsNetbios = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential] $AdfsSvcCredsQualified = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($AdfsSvcCreds.UserName)", $AdfsSvcCreds.Password)
    $Interface = Get-NetAdapter| Where-Object Name -Like "Ethernet*"| Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)
    $ComputerName = Get-Content env:computername
    [Int] $RetryCount = 20
    [Int] $RetryIntervalSec = 30
    [String] $SPTrustedSitesName = "SPSites"
    [String] $ADFSSiteName = "ADFS"
    [String] $AppDomainFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps")
    [String] $AppDomainIntranetFQDN = (Get-AppDomain -DomainFQDN $DomainFQDN -Suffix "Apps-Intranet")

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADDS { Name = "AD-Domain-Services"; Ensure = "Present" }
        WindowsFeature DNS  { Name = "DNS"; Ensure = "Present" }

        Script script1
        {
            SetScript =  {
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics" 
            }
            GetScript =  { @{} }
            TestScript = { $false }
            DependsOn = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools { Name = "RSAT-DNS-Server"; Ensure = "Present" }

        xDnsServerAddress DnsServerAddress 
        {
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn = "[WindowsFeature]DNS"
        }

        xADDomain FirstDS
        {
            DomainName = $DomainFQDN
            DomainAdministratorCredential = $DomainCredsNetbios
            SafemodeAdministratorPassword = $DomainCredsNetbios
            DatabasePath = "C:\NTDS"
            LogPath = "C:\NTDS"
            SysvolPath = "C:\SYSVOL"
            DependsOn = "[xDnsServerAddress]DnsServerAddress"
        }

        xPendingReboot Reboot1
        {
            Name = "RebootServer"
            DependsOn = "[xADDomain]FirstDS"
        }

        xDnsServerPrimaryZone CreateAppsDnsZone
        {
            Name = $AppDomainFQDN
            Ensure= 'Present'
            DependsOn = "[xPendingReboot]Reboot1"
        }

        xDnsServerPrimaryZone CreateAppsIntranetDnsZone
        {
            Name = $AppDomainIntranetFQDN
            Ensure= 'Present'
            DependsOn = "[xDnsServerPrimaryZone]CreateAppsDnsZone"
        }

        #**********************************************************
        # Misc: Set email of AD domain admin and add remote AD tools
        #**********************************************************
        xADUser SetEmailOfDomainAdmin
        {
            DomainAdministratorCredential = $DomainCredsNetbios
            DomainName = $DomainFQDN
            UserName = $Admincreds.UserName
            Password = $Admincreds
            EmailAddress = $Admincreds.UserName + "@" + $DomainFQDN
            PasswordAuthentication = 'Negotiate'
            Ensure = "Present"
            PasswordNeverExpires = $true
            DependsOn = "[xPendingReboot]Reboot1"
        }

        WindowsFeature AddADFeature1    { Name = "RSAT-ADLDS";          Ensure = "Present"; DependsOn = "[xPendingReboot]Reboot1" }
        WindowsFeature AddADFeature2    { Name = "RSAT-ADDS-Tools";     Ensure = "Present"; DependsOn = "[xPendingReboot]Reboot1" }

        xADUser CreateAdfsSvcAccount
        {
            DomainAdministratorCredential = $DomainCredsNetbios
            DomainName = $DomainFQDN
            UserName = $AdfsSvcCreds.UserName
            Password = $AdfsSvcCreds
            Ensure = "Present"
            PasswordAuthentication = 'Negotiate'
            PasswordNeverExpires = $true
            DependsOn = "[xPendingReboot]Reboot1"
        }

        Group AddAdfsSvcAccountToDomainAdminsGroup
        {
            GroupName='Administrators'   
            Ensure= 'Present'             
            MembersToInclude= $AdfsSvcCredsQualified.UserName
            Credential = $DomainCredsNetbios    
            PsDscRunAsCredential = $DomainCredsNetbios
            DependsOn = "[xADUser]CreateAdfsSvcAccount"
        }

        xDnsRecord AddADFSHostDNS {
            Name = $ADFSSiteName
            Zone = $DomainFQDN
            Target = $PrivateIP
            Type = "ARecord"
            Ensure = "Present"
            DependsOn = "[xPendingReboot]Reboot1"
        }        
    }
}

function Get-NetBIOSName
{
    [OutputType([string])]
    param(
        [string]$DomainFQDN
    )

    if ($DomainFQDN.Contains('.')) {
        $length=$DomainFQDN.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainFQDN.Substring(0,$length)
    }
    else {
        if ($DomainFQDN.Length -gt 15) {
            return $DomainFQDN.Substring(0,15)
        }
        else {
            return $DomainFQDN
        }
    }
}

function Get-AppDomain
{
    [OutputType([string])]
    param(
        [string]$DomainFQDN,
        [string]$Suffix
    )

    $appDomain = [String]::Empty
    if ($DomainFQDN.Contains('.')) {
        $domainParts = $DomainFQDN.Split('.')
        $appDomain = $domainParts[0]
        $appDomain += "$Suffix."
        $appDomain += $domainParts[1]
    }
    return $appDomain
}

<#
# Azure DSC extension logging: C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC\2.21.0.0
# Azure DSC extension configuration: C:\Packages\Plugins\Microsoft.Powershell.DSC\2.21.0.0\DSCWork

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name xAdcsDeployment
Install-Module -Name xCertificate
Install-Module -Name xPSDesiredStateConfiguration
Install-Module -Name xCredSSP
Install-Module -Name xWebAdministration
Install-Module -Name xDisk
Install-Module -Name xNetworking

help ConfigureDCVM

$Admincreds = Get-Credential -Credential "yvand"
$AdfsSvcCreds = Get-Credential -Credential "adfssvc"
$DomainFQDN = "contoso.local"
$PrivateIP = "10.0.1.4"

ConfigureDCVM -Admincreds $Admincreds -AdfsSvcCreds $AdfsSvcCreds -DomainFQDN $DomainFQDN -PrivateIP $PrivateIP -ConfigurationData @{AllNodes=@(@{ NodeName="localhost"; PSDscAllowPlainTextPassword=$true })} -OutputPath "C:\Packages\Plugins\Microsoft.Powershell.DSC\2.71.1.0\DSCWork\ConfigureDCVM.0\ConfigureDCVM"
Set-DscLocalConfigurationManager -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC\2.71.1.0\DSCWork\ConfigureDCVM.0\ConfigureDCVM"
Start-DscConfiguration -Path "C:\Packages\Plugins\Microsoft.Powershell.DSC\2.71.1.0\DSCWork\ConfigureDCVM.0\ConfigureDCVM" -Wait -Verbose -Force

https://github.com/PowerShell/xActiveDirectory/issues/27
Uninstall-WindowsFeature "ADFS-Federation"
https://msdn.microsoft.com/library/mt238290.aspx
\\.\pipe\MSSQL$MICROSOFT##SSEE\sql\query
#>
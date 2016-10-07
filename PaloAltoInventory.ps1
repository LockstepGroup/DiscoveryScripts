
[CmdletBinding()]
<#
    .SYNOPSIS
        Gets inventory information from PA Firewalls/Panorama
#>

Param (
    [Parameter(Mandatory=$True,Position=0,ParameterSetName="cred")]
    [Parameter(Mandatory=$True,Position=0,ParameterSetName="apikey")]
    [Parameter(Mandatory=$True,Position=0,ParameterSetName="credcw")]
    [Parameter(Mandatory=$True,Position=0,ParameterSetName="apikeycw")]
    [array]$Device,

    [Parameter(Mandatory=$True,Position=1,ParameterSetName="cred")]
    [Parameter(Mandatory=$True,Position=1,ParameterSetName="credcw")]
    [System.Management.Automation.CredentialAttribute()]$Credential,

    [Parameter(Mandatory=$True,Position=1,ParameterSetName="apikey")]
    [Parameter(Mandatory=$True,Position=1,ParameterSetName="apikeycw")]
    [string]$ApiKey,

    [Parameter(Mandatory=$False,Position=2,ParameterSetName="credcw")]
    [Parameter(Mandatory=$False,Position=2,ParameterSetName="apikeycw")]
    [switch]$ConnectWise,

    [Parameter(Mandatory=$True,Position=3,ParameterSetName="credcw")]
    [Parameter(Mandatory=$True,Position=3,ParameterSetName="apikeycw")]
    [string]$Organization,

    [Parameter(Mandatory=$False,Position=4,ParameterSetName="cred")]
    [Parameter(Mandatory=$False,Position=4,ParameterSetName="apikey")]
    [Parameter(Mandatory=$False,Position=4,ParameterSetName="credcw")]
    [Parameter(Mandatory=$False,Position=4,ParameterSetName="apikeycw")]
    [string]$CsvPath
)

$VerbosePrefix = "PaloAltoInventory:"

if (!(gmo PowerAlto2)) {
    try {
        ipmo poweralto2 | Out-Null
    } catch {
        Throw $Error[0].Exception
    }
}

if ($CsvPath) {
    $TestPath = Test-Path $CsvPath -PathType Container
    if (!($TestPath)) {
        Throw "$VerbosePrefix CsvPath is not a valid directory."
    }
}


function GetFirewallInventory {
    [CmdletBinding()]
    <#
        .SYNOPSIS
            Gets inventory information from PA Firewalls/Panorama
    #>

    Param (
        [Parameter(Mandatory=$True,Position=0)]
        $DeviceObject
    )

    $ReturnObject                = "" | Select Configurations,Licenses
    $ReturnObject.Configurations = @()
    $ReturnObject.Licenses       = @()

    # Create new object and add it to return array
    $NewConfiguration        = "" | Select name,configuration_type,configuration_status, `
                                    hostname,primary_ip,default_gateway,mac_address,serial_number, `
                                    asset_tag,manufacturer,model,operating_system,operating_system_notes, `
                                    notes,installed_by,purchased_by,warranty_expires_at,location
    
    $ReturnObject.Configurations += $NewConfiguration

    # Static Configuration information
    $NewConfiguration.configuration_type   = "Firewall"
    $NewConfiguration.configuration_status = "Active"
    $NewConfiguration.manufacturer         = "Palo Alto Networks"

    # Information returned from PaDeviceObject
    $NewConfiguration.name                   = $DeviceObject.Name
    $NewConfiguration.hostname               = $DeviceObject.Name
    $NewConfiguration.serial_number          = $DeviceObject.Serial
    $NewConfiguration.primary_ip             = $DeviceObject.IpAddress
    $NewConfiguration.model                  = $DeviceObject.Model
    $NewConfiguration.operating_system       = $DeviceObject.OsVersion
    $NewConfiguration.operating_system_notes = "PanOS " + $DeviceObject.OsVersion

    # Information from raw query
    $RawPaDevice = ([xml]($DeviceObject.RawQueryHistory[0])).response.result.system

    $NewConfiguration.default_gateway = $RawPaDevice.'default-gateway'
    $NewConfiguration.mac_address     = $RawPaDevice.'mac-address'

    # Add location
    try {
        Write-Verbose "$VerbosePrefix location"
        $PaLocation = Get-PaConfig -Xpath '/config/devices/entry/deviceconfig/system/snmp-setting/snmp-system/location'
        Write-Verbose "$VerbosePrefix got location"
        $NewConfiguration.location = $PaLocation.location
    } catch {

    }

    

    #######################################################
    # Get Support License information
    Write-Verbose "$VerbosePrefix support"
    $Support   = Invoke-PaOperation "<request><support><check></check></support></request>"
    Write-Verbose "$VerbosePrefix got support"
    $Support   = $Support.SupportInfoResponse.Support
    
    $NewLicense = "" | Select Manufacturer,Name,Version,Seats,
                              "License Key(s)","Purchase Date","Renewal Date",
                              "Renewal Cost","Associated Hardware"

    $NewLicense.manufacturer          = "Palo Alto Networks"
    $NewLicense.Name                  = $Support.SupportLevel + " Support"
    $NewLicense."Renewal Date"        = $Support.ExpiryDate
    $NewLicense."Associated Hardware" = $NewConfiguration.name

    $ReturnObject.Licenses += $NewLicense
    
    #######################################################
    # Get other License information
    Write-Verbose "$VerbosePrefix licenses"
    $Licenses = Invoke-PaOperation "<request><license><info></info></license></request>"
    Write-Verbose "$VerbosePrefix got licenses"
    $Licenses = $Licenses.licenses.entry
    foreach ($License in $Licenses) {
        $NewLicense = "" | Select Manufacturer,Name,Version,Seats,
                                  "License Key(s)","Purchase Date","Renewal Date",
                                  "Renewal Cost","Associated Hardware"

        $NewLicense.manufacturer          = "Palo Alto Networks"
        $NewLicense.Name                  = $License.feature
        $NewLicense."License Key(s)"      = $License.authcode
        $NewLicense."Purchase Date"       = $License.issued
        $NewLicense."Renewal Date"        = $License.expires
        $NewLicense."Associated Hardware" = $NewConfiguration.name

        $ReturnObject.Licenses += $NewLicense
    }

    return $ReturnObject
}


$ReturnObject                = "" | Select Configurations,Licenses
$ReturnObject.Configurations = @()
$ReturnObject.Licenses       = @()

foreach ($Item in $Device) {
    $ConnectParams = @{}
    $ConnectParams.Device = $Item
    if ($Credential) {
        $ConnectParams.PaCred = $Credential
    } else {
        $ConnectParams.ApiKey = $ApiKey
    }
    $Connect = Get-PaDevice @ConnectParams

    $CurrentDevice = $Global:PaDeviceObject
    switch ($CurrentDevice.Type) {
        'firewall' {
            $GetInventory = GetFirewallInventory $Global:PaDeviceObject
            $ReturnObject.Configurations += $GetInventory.Configurations
            $ReturnObject.Licenses += $GetInventory.Licenses
        }
        'panorama' {
            $GetInventory = GetFirewallInventory $Global:PaDeviceObject
            $ReturnObject.Configurations += $GetInventory.Configurations
            $ReturnObject.Licenses += $GetInventory.Licenses

            $ManagedDevices = Get-PaManagedDevices
            foreach ($ManagedDevice in $ManagedDevices) {
                $ConnectParams.Device = $ManagedDevice.IpAddress
                $Connect = Get-PaDevice @ConnectParams
                $GetInventory = GetFirewallInventory $Global:PaDeviceObject
                $ReturnObject.Configurations += $GetInventory.Configurations
                $ReturnObject.Licenses += $GetInventory.Licenses
            }
        }
    }
}

if ($ConnectWise) {
    $NewConfigurations = @()
    foreach ($Configuration in $ReturnObject.Configurations) {
        $NewConfiguration = "" | Select "Configuration Type","Configuration Name","Manufacturer Company Name", `
                                        "Serial Number","Model Number","Tag Number","Purchase Date", `
                                        "Installed Date","Installed By","Warranty Date","Configuration Status", `
                                        "Company Name","Contact First Name","Contact Last Name", `
                                        "Company Address Site Name",Location,Group,"Configuration Notes"
        $NewConfigurations += $NewConfiguration

        $NewConfiguration."Configuration Type"        = "Firewall"
        $NewConfiguration."Configuration Name"        = $Configuration.name
        $NewConfiguration."Manufacturer Company Name" = "Palo Alto Networks"
        $NewConfiguration."Serial Number"             = $Configuration.serial_number
        $NewConfiguration."Model Number"              = $Configuration.model
        $NewConfiguration."Company Name"              = $Organization
        $NewConfiguration.Location                    = $Configuration.location

        $ReturnObject.Configurations = $NewConfigurations
    }
}

if ($CsvPath) {
    Write-Verbose "$VerbosePrefix CsvPath: $CsvPath"
    $ResolvedCsvPath   = Resolve-Path $CsvPath
    $ConfigurationPath = $ResolvedCsvPath.Path + "\Configurations.csv"
    $LicensePath       = $ResolvedCsvPath.Path + "\Licenses.csv"

    $ReturnObject.Configurations | Export-Csv -Path $ConfigurationPath -NoTypeInformation
    $ReturnObject.Licenses       | Export-Csv -Path $LicensePath -NoTypeInformation
}

return $ReturnObject
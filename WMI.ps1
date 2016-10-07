$IpRx = [regex] "(\d{1,3}\.){3}\d{1,3}"
$BadIpRx = [regex] "^169\."
$Shortname = [regex] "([^\.]+)"
ipmo ipv4math

$VRF = "def-880-cor-001"
$Tenant = "DEF Law"
$Domain = "deflaw.local"
$Computers = @()
$Computers += "defatew01"
$Computers += "defatts02"
$Computers += "defatts01"
$Computers += "deatdi01"
$Computers += "defatdc01"

$NetboxOutput = @()
$ItGlueOutput = @()

foreach ($c in $Computers) {
	$c += ".deflaw.local"
	$ShortComputerName = $Shortname.Match($c).Value
	try {
		$NACs = gwmi -Class Win32_NetworkAdapterConfiguration -credential $cred -namespace "root\CIMV2" -computername $c -Filter "IPEnabled = 'True'"
		$NAs  = gwmi -Class win32_networkadapter -credential $cred -ComputerName $c
		foreach ($n in $NACs) {
			$DefaultGateway = $NACs.DefaultIpGateway[0]
		
			$Adapter = $NAs | ? { $_.Index -eq $n.Index }
			
			$IPs = @()
			$i = 0
			foreach ($IP in $n.IPAddress) {
				if ($IpRx.Match($IP).Success -and !($BadIpRx.Match($IP).Success)) {
					$NewObject = "" | Select Address,VRF,Tenant,Device,Interface,IsPrimary,Description
					$CurrentIP = $IP + "/"
					$CurrentIP += (ConvertTo-MaskLength $n.IPSubnet[$i])
					
					$NewObject.Address     = $CurrentIP
					$NewObject.Vrf         = $VRF
					$NewObject.Tenant      = $Tenant
					$NewObject.Device      = $ShortComputerName
					$NewObject.Interface   = "nic" + $n.Index
					$NewObject.Description = $n.Description
					
					$NetboxOutput += $NewObject
				}
				$i++
			}
		}
	} catch {
		$New = "" | Select hostname,primary_ip,default_gateway,mac_address, `
						   serial_number,asset_tag,manufacturer,model,operating_system,notes
		$New.notes = "COULD NOT CONNECT WMI"
		$New.hostname = $c
		
		$ItGlueOutput += $New
	}
}

$Output | Export-Csv test.csv -NoTypeInformation
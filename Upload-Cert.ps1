<#
.SYNOPSIS
Imports a certificate into the firewall and updates WAF rules. Can also update the certificate of the admin and user portal.
.DESCRIPTION
Imports a certificate into the firewall and updates WAF rules.
Takes either a X509Certificate2 object as a parameter or from the pipe, a path and password to a .pfx file, a certificate thumbprint or a FriendlyName search term.
Can update the certificate of the admin and user portal and delete obsolete certificates.

(c) 2023 Martin Walter
https://mwcs.de

.PARAMETER Uri
The URI of the firewall API. Usually "https://<firewall>:4444/webconsole/APIController"

.PARAMETER Credential
The credentials of a firewall API user.

.PARAMETER CertificateThumbprint
The exact thumbprint of the certificate to be imported. The script will look for the certificate in the Personal store.

.PARAMETER CertificateFriendlyName
Part of the friendly name of the certificate to be imported. The script will search for a certificate containing the phrase in the Personal store.
If multiple matches are found, the certificate with the longest valid endtime is selected.

.PARAMETER PfxPath
Path to a .pfx file to be used. Use with PfxPassword

.PARAMETER PfxPassword
Password of the .pfx file.

.PARAMETER Certificate
A X509Certificate2 object

.PARAMETER FriendlyName
Friendly name to use when importing the cert. Will be prefixed with the current year and date.
If this parameter is not set, the CN of the certificate will be used.

.PARAMETER Exact
Include this switch parameter if the FriendlyName parameter is the eacte FriendlyName of the certificate

.PARAMETER RulesGroup
Name of the group to put WAF rules into.

.PARAMETER UpdateAdminCertificate
Include this switch parameter to update the admin and user portal cert

.PARAMETER DeleteOldCertificates
Include this switch parameter to delete obsolete certs that were used by updated WAF rules

.INPUTS
A X509Certificate2 object

.EXAMPLE 
Upload-Cert.ps1 <uri> <credential> -CertificateFriendlyName "R3"

Search in the Central Certificate Store for a certificate containing "R3" in the FriendlyName and import it into the firewall.
Set it to all WAF rules where the certificate is valid for every domain used.

.EXAMPLE 
Upload-Cert.ps1 <uri> <credential> <certThumbprint> -FriendlyName "My imported cert" -RulesGroup "WAFs" -UpdateAdminCertificate -DeleteOldCertificates

Search in the Central Certificate Store for a certificate containing with the given thumbprint and import it into the firewall.
Set it to all WAF rules where the certificate is valid for every domain used.
Also set the certificate for the admin and user portal and delete any certificates that were used by the rules before the update.

.EXAMPLE 
Upload-Cert.ps1 <uri> <credential> -PfxPath <path> -PfxPassword <password> -RulesGroup "WAFs" -UpdateAdminCertificate -DeleteOldCertificates

Load the .pfx file and import it into the firewall.
Set it to all WAF rules where the certificate is valid for every domain used.
Move the updated rules into the group "WAFs".
Also set the certificate for the admin and user portal and delete any certificates that were used by the rules before the update.

.LINK
https://mwcs.de
https://github.com/mwcs4/SFOS-upload-certificate
#>

[CmdletBinding(DefaultParameterSetName = 'FriendlyName')]
param(
	[Parameter(Mandatory, Position = 0)]
	[string]
	$Uri,

	[Parameter(Mandatory, Position = 1)]
	[ValidateNotNull()]
	[System.Management.Automation.PSCredential]
	[System.Management.Automation.Credential()]
	$Credential,

	[Parameter(Mandatory, ParameterSetName = 'Thumbprint', Position = 2)]
	[string]
	$CertificateThumbprint,
	
	[Parameter(Mandatory, ParameterSetName = 'FriendlyName', Position = 2)]
	[string]
	$CertificateFriendlyName,

	[Parameter(Mandatory = $false, ParameterSetName = 'FriendlyName', Position = 3)]
	[switch]
	$Exact,

	[Parameter(Mandatory, ParameterSetName = 'Pfx', Position = 2)]
	[string]
	$PfxPath,
	
	[Parameter(Mandatory, ParameterSetName = 'Pfx', Position = 3)]
	[securestring]
	$PfxPassword,

	[Parameter(ValueFromPipeline=$true, Mandatory, ParameterSetName = 'Certificate', Position = 2)]
	[System.Security.Cryptography.X509Certificates.X509Certificate2]
	$Certificate,

	[Parameter(Mandatory = $false)]
	[string]
	$FriendlyName,

	[Parameter(Mandatory = $false)]
	[string]
	$RulesGroup,

	[switch]
	$UpdateAdminCertificate,

	[switch]
	$DeleteOldCertificates
)

if ($PSVersionTable.PSVersion.Major -lt 7)
{
	Write-Error "Please upgrade Powershell version. Minimum required version is v7.0"
	exit
}

function GeneratePassword {
    param(
        [ValidateRange(12, 256)]
        [int] 
        $length = 14
    )

	$symbols = '!@#$%^&*'.ToCharArray()
	$characterList = 'a'..'z' + 'A'..'Z' + '0'..'9' + $symbols
    do {
        $password = -join (0..$length | ForEach-Object { $characterList | Get-Random })
        [int]$hasLowerChar = $password -cmatch '[a-z]'
        [int]$hasUpperChar = $password -cmatch '[A-Z]'
        [int]$hasDigit = $password -match '[0-9]'
        [int]$hasSymbol = $password.IndexOfAny($symbols) -ne -1
    }
    until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge 3)

    $password
}


function ToArray {
	begin {
		$output = @();
	}
	process {
		$output += $_;
	}
	end {
		return ,$output;
	}
}


function ContainsAll([string[]] $List, [string[]]$Search) {

	if ($null -eq $Search) {
		return $false
	}

	if ($Search.Count -eq 0) {
		return $false
	}

	foreach ($Element in $Search) {
		if ($List -notcontains $Element) {
			return $false
		}
	}
	return $true
}


class FirewallApi {
	[string]$Uri
	[System.Management.Automation.PSCredential]$Credential

	hidden $UsedCertificates = @()
	hidden $WAFRules = @()
	
	[string]XmlStart() {
		$UserName = $this.Credential.UserName
		$Password = $this.Credential.Password | ConvertFrom-SecureString -AsPlainText
		return "<Request><Login><Username>$UserName</Username><Password>$Password</Password></Login>"
	}

	[string]XmlEnd() {
		return '</Request>'
	}

	[xml]Post([System.Collections.IDictionary]$Form) {
		return Invoke-RestMethod -Uri $this.Uri -Method Post -Form $Form -SkipCertificateCheck -verbose:$false
	}

	[xml]Get([System.Collections.IDictionary]$Form) {
		return Invoke-RestMethod -Uri $this.Uri -Form $Form -SkipCertificateCheck -verbose:$false
	}

	[System.Collections.IDictionary]BuildForm([string]$Query) {
		$Request = $this.XmlStart() + $Query + $this.XmlEnd()

		$Form = @{
			reqxml = $Request
		}

		return $Form
	}

	[xml]Query([string]$Query) {
		$Form = $this.BuildForm($Query)
		
		return $this.Get($Form)
	}

	[int]UploadCertificate([string]$PathName, [securestring]$Password, [string]$DisplayName) {
		Write-Verbose "Uploading Certificate as `"$DisplayName`""
		$BaseName = $((Get-Item $PathName).Basename)

		$Pass = $Password | ConvertFrom-SecureString -AsPlainText
		$Query = "<Set operation=`"add`"><Certificate><Action>UploadCertificate</Action><Name>$DisplayName</Name><CertificateFormat>pkcs12</CertificateFormat><CertificateFile>$BaseName.pfx</CertificateFile><Password>$Pass</Password></Certificate></Set>"

		$Form = $This.BuildForm($Query)
		$Form[$BaseName] = Get-Item -Path $PathName

		$Result = $this.Post($Form)

		$StatusCode = $Result.Response.Certificate.Status
		switch ($StatusCode.Code) {
			"200" {
				Write-verbose "Certificate uploaded sucessfully."
				return 0
			}
			"502" {
				Write-Verbose "Certificate with that name already exists."
				return 1
			}
		}
		Write-Verbose "Certificate upload failed with error $($StatusCode.Code): `"$($StatusCode.InnerText)`""
		return -1
	}

	[System.Xml.XmlNode[]]GetWAFRules() {
		Write-Verbose "Retrieving WAF rules"
		$Query = '<Get><FirewallRule></FirewallRule></Get>';

		$Result = $this.Query($Query)

		return $Result.Response.FirewallRule | Where-Object PolicyType -eq 'HTTPBased'
	}

	[bool]UpdateRuleCertificate([System.Xml.XmlNode]$Rule, [string]$Certificate) {
		Write-Verbose "Updating Certificate for rule `"$($Rule.Name)`""
		$CurrentCertName = $Rule.HTTPBasedPolicy.Certificate

		if ($CurrentCertName -eq $Certificate) {
			return $true
		}
	
		$this.UsedCertificates += $CurrentCertName
		$this.WAFRules += $Rule.Name

		$Rule.Attributes.RemoveNamedItem('transactionid')

		$CertNode = $Rule.HTTPBasedPolicy.SelectSingleNode("Certificate")
		$CertNode.InnerText = $Certificate
		[string]$Xml = $Rule.OuterXml
		
		$Query = "<Set operation=`"Update`">$Xml</Set>"

		$Result = $this.Query($Query)
		$StatusCode = $Result.Response.FirewallRule.Status
	
		$Ok = $StatusCode.Code -eq "200"
		if (-not $Ok) {
			Write-Verbose "Certificate update of rule `"$($Rule.Name)`" failed with error $($StatusCode.Code): `"$($StatusCode.InnerText)`""
		}
		return $Ok
	}

	[bool]UpdateRulesCertificate([System.Xml.XmlNode[]]$Rules, [string]$Certificate, [string[]]$DomainNames) {
		$ReturnValue = $true

		foreach ($Rule in $Rules) {
			$Domain = $Rule.HTTPBasedPolicy.Domains.Domain
		
			if (ContainsAll $DomainNames $Domain) {
				$ReturnValue = $ReturnValue -and $this.UpdateRuleCertificate($Rule, $Certificate)
			}
		}
		return $ReturnValue
	}

	[bool]UpdateWAFRules([string]$Certificate, [string[]]$DomainNames) {
		$Rules = $this.GetWAFRules()

		return $this.UpdateRulesCertificate($Rules, $Certificate, $DomainNames)
	}

	[bool]UpdateAdminCertificate([string]$Certificate) {
		Write-Verbose "Updating Certificate of admin and user portal"
		$Query = '<Get><AdminSettings></AdminSettings></Get>'
		$Result = $this.Query($Query)

		$AdminSettings = $Result.Response.AdminSettings

		$nodes = $AdminSettings.ChildNodes | ToArray
		foreach ($node in $nodes | Where-Object { $_.Name -ne "WebAdminSettings"}) {

			$null = $node.ParentNode.RemoveChild($node)
		}
		$AdminSettings.Attributes.RemoveNamedItem('transactionid')

		$CertNode = $AdminSettings.WebAdminSettings.SelectSingleNode('Certificate')
		$CertNode.InnerText = $Certificate
		[string]$Xml = $AdminSettings.OuterXml
		
		$Query = "<Set operation=`"Update`">$Xml</Set>"
		$Result = $this.Query($Query)
		$StatusCode = $Result.Response.WebAdminSettings.Status

		$Ok = $StatusCode.Code -eq "200"
		if (-not $Ok) {
			Write-Verbose "Admin Certificate update failed with error $($StatusCode.Code): `"$($StatusCode.InnerText)`""
		}
		return $Ok
	}

	[bool]MoveRulesToGroup([string]$GroupName) {
		Write-Verbose "Moving rules to group `"$GroupName`""
		if ([string]::IsNullOrEmpty($GroupName)) {
			return $false
		}

		if ($this.WAFRules.Length -eq 0) {
			return $false
		}
	
		$Query = '<Get><FirewallRuleGroup></FirewallRuleGroup></Get>'
		$Result = $this.Query($Query)
	
		[System.Xml.XmlNode]$FirewallGroup = ($Result.Response.FirewallRuleGroup | Where-Object Name -eq $GroupName | Select-Object -First 1)

		if ($null -eq $FirewallGroup) {
			return $false
		}

		$FirewallGroup.Attributes.RemoveNamedItem('transactionid')

		$SecurityPolicyList = $FirewallGroup.SecurityPolicyList

		foreach ($WAFRule in $this.WAFRules) {
			$Newnode = $FirewallGroup.OwnerDocument.CreateElement('SecurityPolicy')

			$Newnode.InnerText = $WAFRule

			$SecurityPolicyList.AppendChild($Newnode)
		}

		[String]$Xml = $FirewallGroup.OuterXml
		
		$Query = "<Set operation=`"Update`">$Xml</Set>"
		
		$Result = $this.Query($Query)
		$StatusCode = $Result.Response.FirewallRuleGroup.Status

		$Ok = $StatusCode.Code -eq "200"
		if (-not $Ok) {
			Write-Verbose "Moving rules to group `"$GroupName`" failed with error $($StatusCode.Code): `"$($StatusCode.InnerText)`""
		}
		return $Ok
	}

	[bool]DeleteCertificates() {
		$ReturnValue = $true
		$ExpCerts = $this.UsedCertificates | Select-Object -Unique

		foreach ($ExpCert in $ExpCerts) {
			Write-Verbose "Deleting obsolete Certificate `"$ExpCert`""
			$Query = "<Remove><Certificate><Name>$ExpCert</Name></Certificate></Remove>"

			$Result = $this.Query($Query)
			$StatusCode = $Result.Response.Certificate.Status

			$Ok = $StatusCode.Code -eq "200"
			if (-not $Ok) {
				Write-Verbose "Deleting Certificate `"$ExpCert`" failed with error $($StatusCode.Code): `"$($StatusCode.InnerText)`""
				$ReturnValue = $false
			}
		}

		return $ReturnValue
	}
}

class ManagedCertificate {
	[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
	[securestring]$Password
	[string]$FilePath

	ManagedCertificate([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
		$this.Certificate = $Certificate
	}

	[void]ExportCertificateToTempFile() {
		$this.FilePath = ([System.IO.Path]::GetTempFileName()).Replace(".tmp", ".pfx")
		$this.Password = (ConvertTo-SecureString -String GeneratePassword -Force -AsPlainText)
		$null = Export-PfxCertificate $this.Certificate -FilePath $this.FilePath -Password $this.Password
	}

	[void]DeleteLastExport() {
		if (-not [string]::IsNullOrEmpty($this.FilePath)) { 
			Remove-Item $this.FilePath
			$this.FilePath = $null
		}
	}

	[string[]]GetCertificateNames() {
		$Subject = $this.Certificate.Subject.Substring(3) # Remove 'CN='

		# Get Subject Alternative Names
		$SAN = ($this.Certificate.Extensions | Where-Object {$_ -is [System.Security.Cryptography.X509Certificates.X509SubjectAlternativeNameExtension]}).Format(1)

		$SAN = $SAN -replace "`n","" -replace "`r",""

		$Names = $SAN.Split("DNS-Name=",[System.StringSplitOptions]::RemoveEmptyEntries)
		$Names += $Subject
		
		return $Names | Select-Object -Unique
	}
}


function LoadCertificate {
	if (-not [string]::IsNullOrEmpty($PfxPath)) {
		# Load Certificate from file
		Write-Verbose "Loading $PfxPath"
		return Get-PfxCertificate -FilePath $PfxPath -Password $PfxPassword
	}
	
	# Load Certificate from storage
	if (-not [string]::IsNullOrEmpty($CertificateThumbprint)) {
		Write-Verbose "Loading Certificate with thumbprint `"$CertificateThumbprint`""
		return Get-ChildItem -Path cert:\localMachine\my\$CertificateThumbprint
	}

	if (-not [string]::IsNullOrEmpty($CertificateFriendlyName)) {
		Write-Verbose "Loading Certificate with FriendlyName containing `"$CertificateFriendlyName`""

		if ($Exact) {
			return (Get-ChildItem -Path cert:\localMachine\my| Sort-Object -Property NotAfter -Descending | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}) | Select-Object -First 1
		}
		return (Get-ChildItem -Path cert:\localMachine\my| Sort-Object -Property NotAfter -Descending | Where-Object {$_.FriendlyName.Contains($CertificateFriendlyName)}) | Select-Object -First 1
	}
}

function Main {
	if ($null -eq $Certificate) {
		$Certificate = LoadCertificate
	}

	if ($null -eq $Certificate) {
		Write-Verbose "No Certificate found. Exiting."
		return
	}

	Write-Verbose "Certificate Thumbprint is `"$($Certificate.Thumbprint)`""

	$ManagedCertificate = [ManagedCertificate]::new($Certificate)

	$DomainNames =  $ManagedCertificate.GetCertificateNames()

	Write-Verbose "Domain names are `"$DomainNames`""

	if ([string]::IsNullOrEmpty($FriendlyName)) {
		$FriendlyName = $Certificate.Subject.Substring(3)
	}

	$DateMonthFormat = (Get-Date -Format yyyy_MM)
	$CertPreFix = $DateMonthFormat + " "
	$CertName = $CertPreFix + $FriendlyName
	
	$FirewallApi = [FirewallApi]::new()
	$FirewallApi.Credential = $Credential
	$FirewallApi.Uri = $Uri

	$ManagedCertificate.ExportCertificateToTempFile()
	$UploadResult = $FirewallApi.UploadCertificate($ManagedCertificate.FilePath, $ManagedCertificate.Password, $CertName)
	$ManagedCertificate.DeleteLastExport()

	if ($UploadResult -ne 0) {
		return
	}
	
	$null = $FirewallApi.UpdateWAFRules($CertName, $DomainNames)
	
	$null = $FirewallApi.MoveRulesToGroup($RulesGroup)
	
	if ($UpdateAdminCertificate) {
		$null = $FirewallApi.UpdateAdminCertificate($CertName)
	}
	
	if ($DeleteOldCertificates) {
		$null = $FirewallApi.DeleteCertificates()
	}
}

Main

<# 
    Created On: 04/08/2021
    Last Updated: 11/16/2021
    Version 0.7.2

    References
        https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ksetup-setenctypeattr
        https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/unsupported-etype-error-accessing-trusted-domain
        https://github.com/dsccommunity/ActiveDirectoryDsc/blob/master/source/DSCResources/MSFT_ADDomainTrust/MSFT_ADDomainTrust.psm1
        https://github.com/dsccommunity/ActiveDirectoryDsc/blob/master/source/Modules/ActiveDirectoryDsc.Common/ActiveDirectoryDsc.Common.psm1
        https://docs.cloudera.com/HDPDocuments/HDP3/HDP-3.1.5/security-reference/content/kerberos_nonambari_set_up_one_way_trust_with_active_directory.html
        https://www.powershellgallery.com/packages/ESAE/0.0.0.17/Content/ESAE.psm1

.KNOWN ISUES
    - Trust validation will bomb out sometimes and prevent AES or Selective Auth from running. Run with the -SkipTrustVerification switch to get around the difference. 

    IN PROGRESS
    v0.7.2
        - More testing (validate)
            AES
            SelectiveAuth
            Test end-to-end with switches
        - Generalize AES and Selective Auth Parameters
            Assume Credential if it isn't provided (use Splatting)
        - This-Side-Only Trust creations
    v0.7.3
        - Create temp users in targe forest?
        - Update Documentation
    TODO
    v0.8.0
        - Module x
        - Selective Auth and AES working as separate functions (Set-PSADTrust) x
        - Verify This-Side-Only Trust creations.
        - Switch to create temp user in target forest with necessary permissions.

    v0.9.0
        - Remote Support - Everything can be run remotely for other environments. 
        - Logging?

    v0.10.0
        - External Trust Support
        - PAM/PIM Trust Support (just a wrapper for netdom)
        - SID Filtering Support
        - SID Quarantine Support
        - Set-PSADTrustSupportedEncryptionTypes cmdlet 
            For re-enabling RC4 (WHY?)

    v0.11.0
        - Shortcut Trust Support
        - Realm Trust Support (???)

#>


#requires -Module ActiveDirectory
using namespace System.DirectoryServices.ActiveDirectory

#region Private Functions (not Exported)
function Set-PSADTrustSelectiveAuthentication
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$TargetForest,

        [Parameter(Mandatory=$false)]
        [object]$SourceForest
    )

    # Variables
    [string]$TargetForestName = ""

    # Determine TargetForest Type
    if( $TargetForest -is "System.String" )
    {
        $TargetForestName = $TargetForest
    }
    else
    {
        $TargetForestName = $TargetForest.Name ## TODO: May error here. Need to do more checks. 
    }

    # Get Source Forest Data
    if( !$SourceForest ) ## TODO: Assuming SourceForest is the correct type.
    {
        $SourceForestInfo = Get-ADTrust -Filter "Name -eq '$TargetForest'"

        ## TODO: What about Realm and Shortcut support?
        if( $SourceForestInfo )
        {
            if( $SourceForestInfo.ForestTransitive )
            {
                $SourceForest = [Forest]::GetCurrentForest()
            }
            else
            {
                $SourceForest = [Domain]::GetCurrentDomain()
            }
            Write-Verbose "Connected to source forest: $($SourceForest.Name)"
        }
        else
        {
            throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("Unable to locate source forest information")
        }
    }
    
    Try
    {
        if( $PSCmdlet.ShouldProcess( $SourceForest.Name,"Enable selective authentication for the $($SourceForest) trust" ) )
        {
            $SourceForest.SetSelectiveAuthenticationStatus($TargetForestName,$true)
            Write-Verbose "Enabled selective authentication on $($SourceForest.Name) for the $TargetForestName trust"
        }
    }
    Catch
    {
        Write-Warning "Failed to enable selective authentication on $($SourceForest.Name) for the $TargetForestName trust"
        
        if( $VerbosePreference )
        {
            foreach( $line in (Out-String -InputObject $PSItem) )
            {
                Write-Verbose -Message $line
            }
        }
    }
}

function Set-PSADTrustAESSupport
{
    <#
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$TargetForestName,

        [Parameter(Mandatory=$true,HelpMessage="Specify the credentials to connect to the local forest")]
        [pscredential]$Credentials,
        
        [Parameter(Mandatory=$false)]
        [switch]$NoOverwrite
    )
    
    # Variables
    [string]$TargetForestName = ""
    $TargetDomainController = $null
    $SourceForest = Get-ADForest -Current LocalComputer

    #region ScriptBlocks
    # This is the magic. We send this ScriptBlock over to the target system for it to run ksetup which does the AES support.
    # These commands MUST be run against a domain controller, nothing else works. 
    $RemoteKsetupSB = { 
        Param( [string]$InboundDomain, [switch]$NoOverwrite )
        [int]$TrustWaitCounter = 0
        while( !(Get-ADTrust -Filter "Name -eq '$InboundDomain'") )
        {
            if( $TrustWaitCounter -lt 6 )
            {
                Start-Sleep -Seconds 5 # Wait ten seconds just in case the trust just hasn't come up yet. 
                $TrustWaitCounter++
            }
            else
            {
                throw [System.InvalidOperationException]::new("Cannot detect a trust for '$InboundDomain'")
            }
        }

        Write-Verbose "Count: $TrustWaitCounter"
        # No Overwrite determines if we want to replace the encryption types or extend them.
        # Default is to replace - RC4 can die in fire.
        if( $NoOverwrite )
        {
            cmd /c "ksetup /addenctypeattr $InboundDomain AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96"
        }
        else
        {
            cmd /c "ksetup /setenctypeattr $InboundDomain AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96"
        }
    }
    #endregion ScriptBlocks

    # Source Forest
    $SourceDomainController = (Get-ADDomainController -Discover -DomainName $SourceForest.Name -Service KDC -ErrorAction Stop).Hostname[0]

    # Determine TargetForest Type
    if( $TargetForest -is "System.String" )
    {
        $TargetForestName = $TargetForest
    }
    else
    {
        $TargetForestName = $TargetForest.Name ## TODO: May error here. Need to do more checks. 
    }


    # Determine TargetForestName's origin
    $TargetTrustInfo = Get-ADTrust -Filter "Name -eq '$TargetForestName'"

    Try
    {
        $TargetDomainController = (Get-ADDomainController -Discover -DomainName $TargetForestName -Service KDC -ErrorAction Stop).Hostname[0]
    }
    Catch
    {
        Write-Error -Message "Failed to connect to target domain '$TargetForestName' - $($PSItem.Exception.Message)"
        throw $PSItem
    }


    if( !$TargetTrustInfo )
    {
        throw "Unable to locate trust information for '$TargetForestName'"
    }
    elseif( $TargetTrustInfo.Direction -eq "Outbound" )
    {
        if( !$Credentials )
        {
            $Credentials = Get-Credential -Message "Provide Administrative Credentials for $TargetForestName"
        }

        $TargetTrustInfo = Get-ADTrust -Filter "Name -eq '$TargetForestName'" -Server $TargetDomainController -Credential $Credentials
    }
    ## TODO: Bidirectional/Inbound?

    Write-Verbose "Setting AES Support on for '$TargetForestName in the domain: $($SourceForest.Name)"
    if( $TargetTrustInfo.Direction -eq "Bidirectional" -or $TargetTrustInfo.Direction -eq "Inbound" )
    {
        $LocalServerType = (Get-CimInstance -ClassName Win32_ComputerSystem -Property DomainRole).DomainRole
        if( $LocalServerType -ge 4 )
        {
            $AESStatus = Invoke-Command -ScriptBlock $RemoteKsetupSB -ArgumentList $TargetForestName,$NoOverwrite -Verbose:$VerbosePreference
        }
        else
        {
            $AESStatus = Invoke-Command -ComputerName $SourceDomainController -Credential $Credentials -ScriptBlock $RemoteKsetupSB -ArgumentList $TargetForestName,$NoOverwrite -Verbose:$VerbosePreference
        }
    }

    Write-Verbose (Out-String -InputObject (($AESStatus -join " ").replace("\s","")))

    if( $AESStatus -like "*failed*" )
    {
        throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("Failed to configure encryption types for $TargetForestName in $($SourceForest.Name) - $($AESStatus[0])")
    }
    else
    {
        $AESCheck = Get-ADObject -LDAPFilter "(&(objectClass=trustedDomain)(name=$TargetForestName))" -Properties msDS-SupportedEncryptionTypes -Server $SourceDomainController -Credential $Credentials
        if( !($AESCheck.'msDS-SupportedEncryptionTypes' -band 24) )
        {
            throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("Failed to configure encryption types for $TargetForestName in $($SourceForest.Name) - Cannot find encryption types")
        }
    }
}
#endregion Private Functions

<# 
.SYNOPSIS
Creates trusts between two forests. 

.DESCRIPTION
Creates trusts in any direction between the local forest and a remote forest. Optionally configures selective authentication and configures AES support for the remote forest. 

.PARAMETER TargetForest
[string] Supply the FQDN of the target (remote) forest. 

.PARAMETER TargetForestCredentials
[pscredential] Credentials to authenticate to the target (remote) forest. 

.PARAMETER SourceForest
[string] Optional - Supply the FQDN of the source (local) forest. Reads off the local domain. 

.PARAMETER SourceForestCredentials
[pscredential] Optional - Credentials to authenticate to the (local) forest.

.PARAMETER TrustType
[string] Optional - The type of Trust. Valid options are Forest and External. 

.PARAMETER TrustDirection
[TrustDirection] Defaults to Outbound. The direction of the trust. Inbound, Outbound, and Bidirectional are supported options. 

.PARAMETER CreateLocalOnly
[switch] Creates the trust in the source environment only. Incompatible with Bidirectional trusts. 

.PARAMETER EnableSelectiveAuthentication
[switch] Enables selective authentication on outbound and bidirectional trusts. 

.PARAMETER EnableAESSupport
[switch] Enables AES Support on inbound and bidirectional trusts. 

.PARAMETER SkipTrustVerification
[switch] Skips the trust verification step at the end of the trust. 

.Example
PS> New-ADForest -TargetForest Example.com -TargetForestCredentials (Get-Credential)
Creates an outbound forest trust from the local forest to the remote forest using the supplied credentials. 

.Example
PS> New-ADForest -TargetForest Example.com -TargetForestCredentials (Get-Credential) -TrustDirection Bidirectional
Creates a bidirectional forest trust from the local forest to the remote forest using the supplied credentials. 

.Example
PS> New-ADForest -TargetForest Example.com -TargetForestCredentials (Get-Credential) -TrustDirection Outbound -CreateLocalOnly
Creates an outgoing forest trust from the local forest to the remote forest using the supplied credentials. 
Trust is only created on the local side. 

.Example
PS> New-ADForest -TargetForest Example.com -TargetForestCredentials (Get-Credential) -TrustDirection Inbound -EnableAESSupport
Creates an inbound forest trust from the local forest to the remote forest using the supplied credentials and configures
the trust to support AES encryption types. 

.Example
PS> New-ADForest -TargetForest Example.com -TargetForestCredentials (Get-Credential) -TrustDirection Outbound -EnableSelectiveAuthentication
Creates an outbound forest trust from the local forest to the remote forest using the supplied credentials. 
#>
function New-PSADTrust
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true,HelpMessage="Supply the FQDN of the target (remote) forest")]
        [string]$TargetForest,

        [Parameter(Mandatory=$true,HelpMessage="Credentials to authenticate to the target (remote) forest")]
        [pscredential]$TargetForestCredentials,

        [Parameter(Mandatory=$false,HelpMessage="Supply the FQDN of the source (local) forest. Reads off the local domain")]
        [string]$SourceForest,

        [Parameter(Mandatory=$false,HelpMessage="Credentials to authenticate to the (local) forest")]
        [pscredential]$SourceForestCredentials,

        [Parameter(Mandatory=$false,HelpMessage="The type of Trust. Valid options are Forest and External")]
        [ValidateSet("Forest","External")]
        [string]$TrustType = "Forest",

        [Parameter(Mandatory=$false,HelpMessage="Defaults to Outbound. The direction of the trust. Inbound, Outbound, and Bidirectional are supported options")]
        [TrustDirection]$TrustDirection = "Outbound",

        [Parameter(Mandatory=$false,HelpMessage="Creates the trust in the source environment only. Incompatible with Bidirectional trusts")]
        [switch]$CreateLocalOnly,

        [Parameter(Mandatory=$false,HelpMessage="Enables selective authentication on outbound and bidirectional trusts")]
        [switch]$EnableSelectiveAuthentication,

        [Parameter(Mandatory=$false,HelpMessage="Enables AES Support on inbound and bidirectional trusts")]
        [switch]$EnableAESSupport,

        [Parameter(Mandatory=$false,HelpMessage="Skips the trust verification step at the end of the trust")]
        [switch]$SkipTrustVerification
    )

    # Variables
    [string]$TrustEnvType = ""
    [object]$SourceForestObj = $null # Object is used here because there isn't a good transitional object between Forest and Domain types. 
    [object]$TargetForestObj = $null
    [string]$SourceForestDomainController = ""
    [DirectoryContext]$SourceDirectoryContext = $null
    [string]$TargetForestDomainController = ""
    [DirectoryContext]$TargetDirectoryContext = $null

    # Parameter validation
    if( $TrustDirection -eq "Bidirectional" -and $CreateLocalOnly )
    {
        throw [System.InvalidOperationException]::new("Bidirectional trusts cannot be created on only the local forest")
    }

    switch( $TrustType )
    {
        "External" { $TrustEnvType = "Domain" }
        "Forest" { $TrustEnvType = "Forest" }
        default { 
            throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("No other trust types are supported")
        }
    }

    #region region Source Forest Parameter Validation and Initialization
    if( !$SourceForest )
    {
        switch( $TrustEnvType )
        {
            "Domain" { $SourceForestObj = [Domain]::GetCurrentDomain() }
            "Forest" { $SourceForestObj = [Forest]::GetCurrentForest() }
            default { throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("No other trust types are supported") }
        }
        Write-Verbose "Connected to source forest: $($SourceForestObj.Name)"

        if( $PSBoundParameters.ContainsKey("SourceForestCredentials") )
        {
            Write-Warning -Message "Ignoring paramter 'SoruceForestCredenitals' - No source forest was provided"
        }
    }
    else
    {
        # If we explicitly call out something it gets kind of hard to build our objects without explicit credentials.
        if( !$PSBoundParameters.ContainsKey("SourceForestCredentials") )
        {
            $SourceForestCredentials = Get-Credential -Message "$SourceForest Login Information"
        }

        # Try to resolve the domain controller for the source domain as a validation.
        Try
        {
            $SourceForestDomainController = (Get-ADDomainController -Discover -DomainName $SourceForest -Service KDC -ErrorAction Stop).Hostname[0] # Hostnames come in as arrays, we only want the first name.
        }
        Catch
        {
            Write-Error -Message "Unable to discover a domain controller in '$SourceForest'"
            throw $PSItem
        }

        # Try and Connect the Source to it's appropriate domain.
        $SourceDirectoryContext = [DirectoryContext]::new( $TrustEnvType, $SourceForest, $SourceForestCredentials.UserName, $SourceForestCredentials.GetNetworkCredential().Password )
        Try
        {
            switch( $TrustEnvType )
            {
                "Domain" { $SourceForestObj = [Domain]::GetDomain($SourceDirectoryContext) }
                "Forest" { $SourceForestObj = [Forest]::GetForest($SourceDirectoryContext) }
                default { throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("No other trust types are supported") }
            }
            Write-Verbose "Connected to source forest: $($SourceForestObj.Name)"
        }
        Catch
        {
            Write-Error "Failed to connect to source forest/domain '$SourceForest'"
            throw $PSItem
        }
    }
    #endregion Source Forest Parameter Validation and Initialization

    #region Target Forest Parameter Validation and Initialization
    if( !$CreateLocalOnly )
    {
        # Try to resolve the domain controller for the source domain as a validation.
        Try
        {
            $TargetForestDomainController = (Get-ADDomainController -Discover -DomainName $TargetForest -Service KDC -ErrorAction Stop).Hostname[0] # Hostnames come in as arrays, we only want the first name.
        }
        Catch
        {
            Write-Error -Message "Unable to discover a domain controller in '$TargetForest'"
            throw $PSItem
        }

        $TargetDirectoryContext = [DirectoryContext]::new( $TrustEnvType, $TargetForest, $TargetForestCredentials.UserName, $TargetForestCredentials.GetNetworkCredential().Password )

        Try
        {
            switch( $TrustEnvType )
            {
                "Domain" { $TargetForestObj = [Domain]::GetDomain($TargetDirectoryContext) }
                "Forest" { $TargetForestObj = [Forest]::GetForest($TargetDirectoryContext) }
                default { throw [Microsoft.ActiveDirectory.Management.ADInvalidOperationException]::new("No other trust types are supported") }
            }
            Write-Verbose "Connected to target forest: $($SourceForestObj.Name)"
        }
        Catch
        {
            Write-Error "Failed to connect to remote forest or domain '$TargetForest'"
            throw $PSItem
        }
    }
    else
    {
        Add-Type -AssemblyName "System.Web"

        if( $TrustDirection -eq "Bidirectional" )
        {
            throw [System.InvalidOperationException]::new("Bidirectional trusts cannot be created on only the local forest")
        }
    }
    #endregion Target Forest Parameter Validation and Initialization

    #region Create the Trust
    Try
    {
        if( $PSCmdlet.ShouldProcess( $SourceForestObj.Name, "Create a(n) $($TrustDirection.ToString().ToLower()) trust to $($TargetForestObj.Name)" ) )
        {
            if( !$CreateLocalOnly )
            {
                $SourceForestObj.CreateTrustRelationship( $TargetForestObj, $TrustDirection )
            }
            else
            {
                # Set a random password of 32 characters with a random number of alphanumeric characters in it. 
                [string]$TrustPassword = $TrustPassword = [System.Web.Security.Membership]::GeneratePassword( 32, (Get-Random -Minimum 8 -Maximum 11) )
                $SourceForestObj.CreateLocalSideOfTrustRelationship( $TargetForest, $TrustDirection, $TrustPassword ) # Only need the passed $TargetForest and not the full Object here. 

                # Output the password so it can be forwarded to the other party. Again, high security isn't necessary here.
                # This password is short-lived and superflouous. Once the trust is established it is reset. 
                Write-Host -Object "Trust Password: $TrustPassword" 
            }
            Write-Verbose "Created $($TrustDirection.ToString().ToLower()) from $($SourceForestObj.Name) trust to: $($TargetForestObj.Name)"
        }
    }
    Catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectExistsException]
    {
        Write-Warning "Trust between '$TargetForest' and '$($SourceForestObj.Name)' already exists - Continuing"
    }
    Catch
    {
        Write-Error "Failed to create trust relationship between '$TargetForest' and '$($SourceForestObj.Name)'"
        throw $PSItem
    }
    #endregion Create the Trust

    #region Verify Trust
    if( !$PSBoundParameters.ContainsKey("SkipTrustVerification") -or !$SkipTrustVerification )
    {
        Try
        {
            # Outbound trusts are validated differently.
            if( $TrustDirection -eq "Outbound" -or $TrustDirection -eq "Bidirectional" )
            {
                $SourceForestObj.VerifyOutboundTrustRelationship($TargetForest)
            }
            else
            {
                $SourceForestObj.VerifyTrustRelationship($TargetForestObj,$TrustDirection)
            }
            Write-Verbose "Successfully verified the trust '$TargetForest' in '$($SourceForestObj.Name)'"
        }
        Catch
        {
            Write-Error "Unable to verify trust between $($SourceForestObj.Name) and $TargetForest"
            throw $PSItem
        }
    }
    #endregion VerifyTrust

    #region Selective Authentication
    if( $PSBoundParameters.ContainsKey("EnableSelectiveAuthentication") -and $EnableSelectiveAuthentication )
    {
        if( $TrustDirection -eq "Outbound" )
        {
            Set-PSADTrustSelectiveAuthentication -SourceForest $SourceForestObj -TargetForest $TargetForestObj
        }
        elseif( $TrustDirection -eq "Bidirectional" )
        {
            Set-PSADTrustSelectiveAuthentication -SourceForest $SourceForestObj -TargetForest $TargetForestObj
            Set-PSADTrustSelectiveAuthentication -SourceForest $TargetForestObj -TargetForest $SourceForestObj
        }
        else
        {
            Write-Warning "Selective authentication can only be configured on outbound trusts"
        }
    }
    #endregion Selective Authentication

    #region AES Encryption
    # Checks the 'The other domain supports Kerberos AES Encryption' option on incoming / bidirectional trusts
    if( $PSBoundParameters.ContainsKey("EnableAESSupport") -and $EnableAESSupport )
    {
        if( $TrustDirection -eq "Inbound" )
        {
            if( !$SourceForestCredentials )
            {
                $SourceForestCredentials = Get-Credential -Message "Enter credentials for: $($SourceForestObj.Name)"
            }

            Set-PSADTrustAESSupport -TargetForestName $TargetForest -Credentials $SourceForestCredentials -Verbose:$VerbosePreference
        }
        elseif( $TrustDirection -eq "Bidirectional" )
        {
            if( !$SourceForestCredentials )
            {
                $SourceForestCredentials = Get-Credential -Message "Enter credentials for: $($SourceForestObj.Name)"
            }

            Set-PSADTrustAESSupport -TargetForestName $TargetForest -Credentials $SourceForestCredentials -Verbose:$VerbosePreference
            ## TODO: Need TargetForest AES Modification
        }
        else
        {
            Write-Warning "AES encryption support can only be configured on inbound trusts"
        }
    }
    #endregion AES Encryption
}
Export-ModuleMember -Function New-PSADTrust

function Set-PSADTrust
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,HelpMessage="Supply the FQDN of the target (remote) forest")]
        [string]$TargetForest,

        [Parameter(Mandatory=$false,HelpMessage="Credentials to authenticate to the target (remote) forest")]
        [pscredential]$TargetForestCredentials,

        [Parameter(Mandatory=$false,HelpMessage="Credentials to authenticate to the source (local) forest")]
        [pscredential]$SourceForestCredentials,

        [Parameter(Mandatory=$false,HelpMessage="Enables selective authentication on outbound and bidirectional trusts")]
        [switch]$EnableSelectiveAuthentication,

        [Parameter(Mandatory=$false,HelpMessage="Enables AES Support on inbound and bidirectional trusts")]
        [switch]$EnableAESSupport
    )

    if( $PSBoundParameters.ContainsKey("EnableSelectiveAuthentication") -and $EnableSelectiveAuthentication )
    {
        if( !$TargetForestCredentials )
        {
            $TargetForestCredentials = Get-Credential -Message "$TargetForest - Enter the credentials for the target forest"
        }

        Set-PSADTrustSelectiveAuthentication -TargetForest $TargetForest
    }

    if( $PSBoundParameters.ContainsKey("EnableAESSupport") -and $EnableAESSupport )
    {
        if( !$SourceForestCredentials )
        {
            $SourceForestCredentials = Get-Credential -Message "$((Get-ADForest -Current LocalComputer).Name) - Enter the credentials for the target forest"
        }
        Set-PSADTrustAESSupport -TargetForestName $TargetForest -Credentials $SourceForestCredentials
    }
}
Export-ModuleMember -Function Set-PSADTrust
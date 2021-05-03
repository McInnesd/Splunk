Enum Sharing
{
    global
    system
    app
    user
}

Enum Scheme
{
    https
    http
}

Enum Paths
{
    APPS = "apps/local/"
}

class Context {
    #region Definition of variables

    # The sharing mode for the namespace (the default is "user").
    [Sharing]$Sharing = 'user'

    # The owner context of the namespace (optional, the default is "None").
    [System.String]$Owner = 'None'

    # The app context of the namespace (optional, the default is "None").
    [System.String]$App = 'None'

    # Enable (True) or disable (False) SSL verrification for https connections (the default is "True").
    [bool]$Verify = $true

    # A session token. When provided, you don't need to call login.
    [System.String]$Token

    # A session cookie. When provided, you don't need to call login.
    [System.String]$Cookie

    # The Splunk account username and password, which is used to authenticate the Splunk instance.
    [System.Management.Automation.PsCredential]$Credential

    # Splunk authentication token
    [System.String]$SplunkToken

    # List of extra HTTP headers to send (optional).
    [System.Object[]]$Headers

    # The scheme for accessing the service (the default is "https").
    [Scheme]$Scheme = 'https'

    # The host name (the default is "localhost").
    [System.String]$ComputerName = 'localhost'

    # The port number (the default is 8089).
    [ValidateRange( 1, 65535 )]
    [System.UInt16]$Port = 8089

    # Instance URI
    [System.Uri]$BaseUri = [System.Uri]::new([System.string]::Format('{0}://{1}:{2}',$this.Scheme, $this.ComputerName, $this.Port))

    #endregion

    #region Definition of Constructor
    # Parameterless Constructor
    Context(){
    }

    # Constructor
    Context(
        [System.Management.Automation.PsCredential]$Credential
    ){
        $this.Credential = $Credential
    }

    # Constructor
    Context(
        [System.string]$ComputerName
    ){
        $this.ComputerName = $ComputerName
    }

    # Constructor
    Context(
        [System.string]$ComputerName,
        [System.Management.Automation.PsCredential]$Credential
    ){
        $this.ComputerName = $ComputerName
        $this.Credential = $Credential
        $this.BaseUri = [System.Uri]::new([System.string]::Format('{0}://{1}:{2}',$this.Scheme, $ComputerName, $this.Port))
    }

    #endregion

    #region Definition of Methods
    [void] login()
    {
        $this.Token = $this.login($this.Credential, $this.BaseUri)
    }

    [System.String] login([System.Management.Automation.PsCredential]$Cred, $BaseUri)
    {
        $Url = [System.Uri]::new($BaseUri, '/services/auth/login')
        $Body = @{
            username = $Cred.username
            password = $Cred.GetNetworkCredential().password
        }
        $r = Invoke-RestMethod -Method "POST" -Uri $Url -Body $Body
        return $r.response.sessionKey
        
    }

    #endregion
}


class Service : Context {

    Service(
        [System.string]$ComputerName,
        [System.Management.Automation.PsCredential]$Credential
    ) : base($ComputerName, $Credential)
    {

    }

}

class Endpoint {

    [Service]$Service

    [Paths]$Path
    
}



$Splunk = [Service]::new('splunk-sh01.adhdan.com', $Global:SplunkCred)

$Splunk.login()

$Splunk
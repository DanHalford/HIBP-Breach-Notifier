<#
.SYNOPSIS
Checks to see if any corporate email addresses have been included in reported data breaches. Uses the excellent "Have I Been Pwned" API (https://haveibeenpwned.com/) for source information.

.DESCRIPTION
Checks to see if any corporate email addresses have been included in data breaches reported on Have I Been Pwned. If any breaches are found, an email is sent to the user notifying them of the breach. On subsequent executions, only new breaches are reported.

.PARAMETER SuppressEmails
If specified, no emails will be sent to users. This is useful for testing the script.

.PARAMETER IgnoreBefore
If specified, breaches that occurred before the specified date will be ignored. Legacy breaches will still be written to the database, but will not form part of the alerts sent to the user.

.NOTES
File name: CheckHIBP.ps1
Author: Dan Halford
Pre-requisites:
    This script requires the following modules:
    - Microsoft.Graph.Users
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Users.Actions
    - PSSQLite
    You will also need an API key for "Have I Been Pwned". You can get one at https://haveibeenpwned.com/API/Key.
#>

Param(
    [switch]$SuppressEmails,
    [datetime]$IgnoreBefore
)

Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users.Actions
Import-Module PSSQLite

#region Constants
#API key for "Have I Been Pwned". You can get one at https://haveibeenpwned.com/API/Key
$global:hibpkey = "<<key>>"
#Path to the SQLite database. If the file does not exist, it will be created.
$global:database = "./hibp.db"
#Rate limit in requests per minute. The rate limit is determined by the HIBP subscription type. See https://haveibeenpwned.com/API/Key. The script will check your HIBP subscription and update the rate limit as appropriate
$global:rateLimit = 10
#endregion

<#
.SYNOPSIS
Creates a local SQLite database to store breach data.

.DESCRIPTION
Creates a local SQLite database to store breach data if it does not already exist. Database is created in the path specified in $database.
#>
function New-HIBPDatabase() {
    $sql = @"
CREATE TABLE IF NOT EXISTS breaches (
    breachId UNIQUEIDENTIFIER PRIMARY KEY,
    email TEXT,
    name TEXT,
    title TEXT,
    domain TEXT,
    breachDate DATE,
    addedDate DATE,
    modifiedDate DATE,
    pwnCount INTEGER,
    description TEXT,
    logoPath TEXT,
    dataClasses TEXT,
    isVerified BOOLEAN,
    isFabricated BOOLEAN,
    isSensitive BOOLEAN,
    isRetired BOOLEAN,
    isSpamList BOOLEAN,
    isMalware BOOLEAN
);
"@    
    Invoke-SqliteQuery -DataSource $global:database -Query $sql
}

<#
.SYNOPSIS
Checks the Have I Been Pwned subscription status, and if valid, sets the API rate limit.

.OUTPUTS
True if the subscription is valid, false if not.

#>
function Get-HIBPSubscription() {
    $uri = "https://haveibeenpwned.com/api/v3/subscription/status"
    $headers = @{
        "hibp-api-key" = $hibpkey
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers
        $global:rateLimit = $response.Rpm
        return $true
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
Queries "Have I Been Pwned" for breaches associated with an email address.

.DESCRIPTION
Queries "Have I Been Pwned" for breaches associated with an email address. Returns null if no breaches are found.

.PARAMETER email
The email address to query.

.OUTPUTS
A collection of breach objects, as returned by the Have I Been Pwned API.

.NOTES
If no breaches are found for the specified address, the API returns a 404 error. This is caught and null is returned instead.
#>
function Get-Breaches() {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$email
    )
    $uri = "https://haveibeenpwned.com/api/v3/breachedaccount/$($email)?truncateResponse=false"
    $headers = @{
        "hibp-api-key" = $hibpkey
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers
        return $response
    }
    catch {
        Return $null
    }
}

<#
.SYNOPSIS
Writes a breach to the local SQLite database.

.DESCRIPTION
Writes a breach to the local SQLite database. If the breach already exists in the database, it is not written again.

.PARAMETER breach
The breach object, as returned by the Get-Breaches function.

.PARAMETER email
The email address to associate with the breach.
#>
function Save-Breach() {
    Param(
        [Parameter(Mandatory=$true)]
        [object]$breach,
        [Parameter(Mandatory=$true)]
        [string]$email
    )
    $sql = "SELECT COUNT(*) FROM breaches WHERE email = '$email' AND name = '$($breach.Name)';"
    $breachId = [System.Guid]::NewGuid().ToString()
    $count = Invoke-SqliteQuery -DataSource $database -Query $sql
    Write-Debug "Breach count query returned: $($count.'COUNT(*)')"
    if ($count.'COUNT(*)' -eq 0) {
        $sql = @"
INSERT INTO breaches (
    BreachId,
    email,
    name,
    title,
    domain,
    breachDate,
    addedDate,
    modifiedDate,
    pwnCount,
    description,
    logoPath,
    dataClasses,
    isVerified,
    isFabricated,
    isSensitive,
    isRetired,
    isSpamList
) VALUES (
    '$($breachId)',
    '$email',
    '$($breach.Name)',
    '$($breach.Title.Replace("'", "''"))',
    '$($breach.Domain)',
    '$($breach.BreachDate)',
    '$($breach.AddedDate)',
    '$($breach.ModifiedDate)',
    $($breach.PwnCount),
    '$($breach.Description.Replace("'", "''"))',
    '$($breach.LogoPath)',
    '$($breach.DataClasses -join ",")',
    $([int]$breach.IsVerified),
    $([int]$breach.IsFabricated),
    $([int]$breach.IsSensitive),
    $([int]$breach.IsRetired),
    $([int]$breach.IsSpamList)
);
"@      
$result = Invoke-SqliteQuery -DataSource $database -Query $sql
        
        Return $true
    } else {
        Return $false
    }
}

<#
.SYNOPSIS
Sends an breach detected email to the user.

.DESCRIPTION
Send an breach detected email to the user. The HTML source for the email body is stored in ./breachEmailTemplate.html.

.PARAMETER user
The user object, as returned by the Get-MgUser function.

.PARAMETER breaches
The breaches collection, as returned by the Get-Breaches function.

.NOTES
Emails are sent in the context of the account specified in the Connect-MgGraph function. If you prefer to send from a service account / mailbox, you can modify the -UserId parameter of the Send-MgUserMail function.
#>
function Send-Notification() {
    Param(
        [Parameter(Mandatory=$true)]
        [object]$user,
        [Parameter(Mandatory=$true)]
        [object]$breaches,
        [datetime]$ignoreBefore
    )
    $breachText = "breaches"
    if ($breaches.Count -eq 1) {
        $breachText = "breach"
    }
    $from = Get-MgContext | Select-Object -ExpandProperty Account
    $body = Get-Content -Path ./breachEmailTemplate.html
    $body = $body -replace "{{firstName}}", $user.GivenName
    $body = $body -replace "{{breach}}", $breachText
    $breachRows = ""
    if ($ignoreBefore -ne $null) {
        $breaches = $breaches | Where-Object { [datetime]$_.AddedDate -ge [datetime]$ignoreBefore }
    }
    $breaches | ForEach-Object {
        $breachRows += "<tr><td>$($_.Title)</td><td>$($_.DataClasses -join ", ")</td><td>$($_.BreachDate)</td><td>$($_.Description)</td></tr>"
    }
    $body = $body -replace "{{tablerows}}", $breachRows | Out-String
    $message = @{ Subject = "Security breach detected"}
    $message += @{ Body = @{ ContentType = "HTML"; Content = $body } }
    $message += @{ ToRecipients = @(@{EmailAddress = @{Address = $user.Mail}}) }

    $params = @{
        Message = $message
        SaveToSentItems = $true
    }

    Send-MgUserMail -BodyParameter $params -UserId $from
}

New-HIBPDatabase
$hibpSubscription = Get-HIBPSubscription
if ($hibpSubscription -eq $false) {
    Write-Output "HIBP subscription is invalid"
    exit
}
try {
    if ($SuppressEmails) {
        Connect-MgGraph -NoWelcome -Scopes "User.Read.All"
    } else {
        Connect-MgGraph -NoWelcome -Scopes "User.Read.All, Mail.Send"
    }
}
catch {
    Write-Output "Unable to connect to Graph API"
    exit
}
if ($SuppressEmails) {
    Write-Output "SuppressEmails switch specified - emails will not be sent"
}
$users = Get-MgUser -Select "id,mail,DisplayName,GivenName" | Where-Object { $_.mail -ne $null }

$users | ForEach-Object {
    $email = $_.mail
    Write-Output "Checking breaches for $($email)"
    $breaches = Get-Breaches -email $email
    if ($breaches -eq $null) {
        Write-Output "No breaches found for $($email)"
    } else {
        $newBreachCount = 0
        $newBreaches = @()
        $breaches | ForEach-Object {
            $newBreach = Save-Breach -breach $_ -email $email
            if ($newBreach) {
                $newBreachCount++
                $newBreaches += $_
                Write-Output "New breach found for $($email): $($_.Name)"
            }
        }
        if ($newBreachCount -gt 0) {
            Write-Output "$($newBreachCount) new breaches found for $($email)"
            if (-not $SuppressEmails) {
                Send-Notification -user $_ -breaches $newBreaches -ignoreBefore $IgnoreBefore
            } else {
                Write-Output "Breach summary for $($email):"
                $newBreaches | Where-Object { [datetime]$_.AddedDate -ge [datetime]$IgnoreBefore } | Select-Object Title, BreachDate, AddedDate, DataClasses
            }
        } else {
            Write-Output "No new breaches found for $($email)"
        }
    }
    Start-Sleep -Milliseconds (60000/$rateLimit)
}
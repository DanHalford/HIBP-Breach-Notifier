# Breach Notifier
## Check organisation email addresses against Have I Been Pwned and notify end users of any breaches.

Whlie not directly related to organisational IT security, end users do have a tendancy to re-use passwords between accounts, or at least use passwords that fit a recognised pattern. It is therefore a good idea to scan disclosed breaches to see if any of your organisation's email addresses have been included, and to inform the end user that their data or details might have been compromised.

This script returns details of all users in your Azure tenancy and then utilises the excellent [Have I Been Pwned](https://haveibeenpwned.com/) API to determine if any of them have been included in any breaches. The script will then send the end-user a formatted notification email detailing what breaches have occurred, and any other details HIBP makes available.

Details of each breach are stored in a local SQLite database. When the script is executed again, only details of newly discovered breaches will be sent to the end user.

### Pre-requisites
- User accounts in Azure AD / Entra and mail sent via Exchange Online
- A Have I Been Pwned API key. You can get one here: [Have I Been Pwned - API](https://haveibeenpwned.com/API/Key)
- The **Microsoft Graph Command Line Tools** Enerprise Application will need the *User.Read.All* and *Mail.Send* permissions. But if you haven't configured these already, it will prompt you on first run.
- You will need to install the following PowerShell modules:
    - Microsoft.Graph.Users
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Users.Actions
    - PSSQLite
- From a user comms perspective, consider sending an email saying this service is coming, so they don't immediate bombard your service desk with calls of assistance or phishing reports.

### Instructions

Update the `$hibpkey` variable with your **Have I Been Pwned** API key.
Update the **breachEmailTemplate.html** file to suit your organisation's name and branding.

To avoid your users receiving a notifications of a large number of breaches, consider using the `-suppressEmails` switch to prevent emails being sent the first time you execute the script. Breach details will still be written to the database and displayed on the script output.

To reset the stored breach details, simply delete the SQLite database. The path to the database is specified in the `$database` variable but defaults to **./hibp.db** 

### Notes
Developed on PowerShell 7.3.6 running on MacOS, so should be properly cross-platform compatible.
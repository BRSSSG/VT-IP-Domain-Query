# VT-IP-Domain-Query
Query VirusTotal for checking IP and Domain reputation while analyzing the samples

Powershell script designed to perform VT checks for domains and IP addresses that are connected to endpoint/local machine. Script checks for reputation and logs them in the log file, path provided by the user.


## Features
Checks the tcp connection type on the machine
Performs IP reputation checks through VT 
Performs Domain reputation checks through VT
Save data to a file, path can be provided by the user
Logs and saves various details like PID, LocalIp:Port, RemoteIP:Port, Domain, Date&Time, IP:Reputation, Domain:Reputation


## Prerequisites
PowerShell
VirusTotal API key

## Usage
Open Powershell with admin rights

Change the log file path accordingly

$logFile = "C:\Users\admin\Desktop\network_connections.log"

Replace "VT-API-Key" with VT API key

```markdown
function Get-ApiKey {
    # Replace this with your API key
    return "VT-API-Key"
}


#Run the file in powershell with admin rights
$Query_VT_ip_domain.ps1


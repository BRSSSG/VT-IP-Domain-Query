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

#### Inline Code

Use single backticks for inline code:

```markdown
To install dependencies, run `npm install`.

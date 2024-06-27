# Log file path
$logFile = "C:\temp\network_connections.log"

# Set the interval for monitoring (in seconds)
$interval = 1

# Initialize a hash table to store known connections
$knownConnections = @{}


function Get-ApiKey {
    # Replace this with your API key
    return "VT-API-Key"
}


#return dummy function incase if the IP or domain is not available
function Dummy_Json_object{
    $dummy_response = '{
                "data": {
                           "attributes":{
                                            "last_analysis_stats": {
                                                                    "malicious":-1,  
                                                                    "suspicious":-1
                                                                    }
                                         }

                        }
            }'
    return $dummy_response | ConvertFrom-Json 
}


#Check IP reputation in VT
function QueryIP-VirusTotalApi {
    param (
        [string]$ip
    )

    $apiKey = Get-ApiKey
    $apiIpUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $headers = @{
        "x-apikey" = $apiKey
    }    
    
    try{
        $response = Invoke-RestMethod -Uri $apiIpUrl -Method Get -Headers $headers    
       }
    catch{
        $response = Dummy_Json_object
    }
    
    return $response
}

#Check domain reputation in VT
function QueryDomain-VirusTotalApi {
    param (
        [string]$domain
    )
    
    $apiKey = Get-ApiKey
    $apiDomainUrl = "https://www.virustotal.com/api/v3/domains/$domain"
    $headers = @{
        "x-apikey" = $apiKey
    }
 
    try{
        $response = Invoke-RestMethod -Uri $apiDomainUrl -Method Get -Headers $headers   
        
       }

    catch{
        $response = Dummy_Json_object
    }
    #Write-Output $response
    return $response
}



#Resolve IP to domain
function Resolve-Domain {
    param (
        [string]$ipAddress
    )
    try {
        [System.Net.Dns]::GetHostEntry($ipAddress).HostName
    } catch {
        "None"
    }
}


# Function to get current network connections
function Get-NetworkConnections {
    Get-NetTCPConnection -State Established | ForEach-Object {
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
            PID = $_.OwningProcess
            RemoteDomain = Resolve-Domain -ipAddress $_.RemoteAddress
            
        }
    }
}

# Function to log new connections
function Log-NewConnections {
    param (
        [array]$newConnections
    )

    foreach ($connection in $newConnections) {

            #Exclude VT ip search for local host
            if ($connection.RemoteAddress -match "127.0.0.1"){
                $vt_ip="Clean"
                }
             else{                         
                    
                $ip_reputation = QueryIP-VirusTotalApi -ip $connection.RemoteAddress
                if ($ip_reputation.data.attributes.last_analysis_stats.malicious -gt 0 -or $response.data.attributes.last_analysis_stats.suspicious -gt 0){                 
                    $vt_ip="Dirty"
                }elseif ($ip_reputation.data.attributes.last_analysis_stats.malicious -eq -1 -or $response.data.attributes.last_analysis_stats.suspicious -eq -1){
                    #If IP not available in VT
                    $vt_ip="Not Available"
                }else{
                    $vt_ip="Clean"
                }
             }


           
            #Exclude Desktop- or None domain search 
            if (($connection.RemoteDomain -imatch 'Desktop-') -or ($connection.RemoteDomain -imatch 'None')) {
                    
                    $vt_domain="None"
              
              }else{
                  
                 $domain_reputation = QueryDomain-VirusTotalApi -domain $connection.RemoteDomain                 
                if ($domain_reputation.data.attributes.last_analysis_stats.malicious -gt 0 -or $domain_reputation.data.attributes.last_analysis_stats.suspicious -gt 0){
                    $vt_domain="Dirty"
                }elseif ($domain_reputation.data.attributes.last_analysis_stats.malicious -eq -1 -or $domain_reputation.data.attributes.last_analysis_stats.suspicious -eq -1){
                    #If domain is not availble in VT 
                    $vt_domain="Not Available"
                }else{
                    $vt_domain="Clean"
                    }
             }
 
            #PID of the connection
            $processId = $connection.OwningProcess
            
            #Logging only external connections.

            if ($connection.RemoteAddress -notmatch "127.0.0.1"){ 
                $logEntry = "PID: $($connection.PID), Local: $($connection.LocalAddress):$($connection.LocalPort), Remote: $($connection.RemoteAddress):$($connection.RemotePort), State: $($connection.State), Date: $(Get-Date), RemoteDomain: $($connection.RemoteDomain), VT-IP: $vt_ip, VT-Domain: $vt_domain"
                 Write-Output $logEntry
                 Add-Content -Path $logFile -Value $logEntry
            }
            
            
    }
}

# Continuous monitoring loop
while ($true) {
    # Get current connections
    $currentConnections = Get-NetworkConnections

    # Find new connections
    $newConnections = $currentConnections | Where-Object { -not $knownConnections.ContainsKey("$($_.LocalAddress):$($_.LocalPort)-$($_.RemoteAddress):$($_.RemotePort)") }

    # Log new connections
    if ($newConnections.Count -gt 0) {
        Log-NewConnections -newConnections $newConnections

        # Update the known connections hash table
        foreach ($connection in $newConnections) {
            $key = "$($connection.LocalAddress):$($connection.LocalPort)-$($connection.RemoteAddress):$($connection.RemotePort)"
            $knownConnections[$key] = $true
        }
    }

    # Wait for the next interval
    Start-Sleep -Seconds $interval
}

param([switch]$Verbose,[switch]$Verify,[switch]$CopyOnly,[Switch]$ignoreUser)

#Sleep -s 7200

$workstations = ""
$fromPath = "D:\Scripts\Files\BIOS"
$biosVersions = @{ 
    "Optiplex 3060" = "1.4.2;OptiPlex_3060_1.4.2.exe"; 
    "OptiPlex 3020M" = "A15;OptiPlex_3020M_A15.exe"; 
    "OptiPlex 3040" = "1.11.3;OptiPlex_3040_1.11.3.exe"; 
    "OptiPlex 3050" = "1.12.1;OptiPlex_3050_1.12.1.exe"; 
    "OptiPlex 5050" = "1.12.1;OptiPlex_5050_1.12.1.exe"; 
    "OptiPlex 7010" = "A29;O7010A29.exe"; 
    "OptiPlex 780" = "A15;O780-A15.exe"
    "PowerEdge R230" = "2.7.1;BIOS_DJ7XK_WN64_2.7.1.EXE"
    "PowerEdge R320" = "2.7.0;BIOS_7GHMX_WN64_2.7.0.EXE"
    "PowerEdge R410" = "1.14.0;BIOS_XXNW5_WN64_1.14.0_01.EXE"
    "PowerEdge R510" = "1.14.0;BIOS_PYCXX_WN64_1.14.0_01.EXE"
    "PowerEdge R520" = "2.7.0;BIOS_3X8FN_WN64_2.7.0.EXE"
    "PowerEdge R530" = "2.10.5;BIOS_VH9R0_WN64_2.10.5.EXE"
    "PowerEdge R710" = "6.6.0;BIOS_0F4YY_WN64_6.6.0_01.EXE"
    "PowerEdge R240" = "2.1.6;BIOS_HT9C7_WN64_2.1.6.EXE"
    "Latitude 5580" = "1.16.0;Latitude_5X80_Precision_3520_1.16.0.exe"
    "Latitude 5590" = "1.10.1;Latitude_5X90_1.10.1.exe"
    "Latitude E5570" = "1.21.4;Latitude_E5x70_Precision_3510_1.21.4.exe"
}

$dt = Get-Date -Format yyyyMMddHHmmss
$fn = "Log-$dt.txt"
$count = 0
New-Item -ItemType File -Name $fn | Out-Null


#$workstations = Get-Content .\biosWorkstations.txt

#$workstations = Get-Content .\biosLaptops.txt
#$workstations = Get-Content .\biosLaptopsTest.txt

## Workstations
<# 
$Workstations = Get-ADComputer -Searchbase "OU=PBI  - Workstations,OU=*Premier Bank,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
$Workstations += Get-ADComputer -Searchbase "OU=PBI  - Workstations (Burner/USB Enabled),OU=*Premier Bank,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
$Workstations += Get-ADComputer -Searchbase "OU=CDB - Workstations,OU=*Citzens Deposit Bank,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
$Workstations += Get-ADComputer -Searchbase "OU=CDB - Workstations (Burner/USB Enabled),OU=*Citzens Deposit Bank,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
$Workstations += Get-ADComputer -Searchbase "OU=PFBI - Workstations,OU=*Premier Financial Bancorp\, Inc.,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
$Workstations += Get-ADComputer -Searchbase "OU=PFBI - Workstations (Burner/USB Enabled),OU=*Premier Financial Bancorp\, Inc.,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
#>

## Servers

$workstations = Get-ADComputer -SearchBase "OU=*Information Technology,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
#$workstations += Get-ADComputer -SearchBase "OU=*Alpha-Tech,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name
#$workstations += Get-ADComputer -SearchBase "OU=Domain Controllers,DC=pfbiwv,DC=com" -Filter * -Properties Name | Select -ExpandProperty Name


#$workstations += Get-ADComputers -SearchBase "" -Filter * -Properties Name | Select -ExpandProperty Name

If($Verify){
    Write-Warning "RUNNING IN VERIFY MODE"
}

ForEach($workstation in $workstations){ 
    $runCode = 0
    $latestVersion = ""
    $model = ""
    $currentVersion = ""
    $fileName = ""
    $errDesc = ""
    $user = ""

    ## Ping Workstation - RUNCODE 1
    If(-Not (Test-Connection $workstation -Count 1 -Quiet)){        
            $errDesc = "Computer did not response to ping"
            $runCode = 1
    }

    
    If(-not $CopyOnly){
        If(-not $verify){
            ## Verify No One is Logged On - RUNCODE 10
            $user = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $workstation | Select Username).username
            If( $user -ne $NULL -AND $user -ne "")
            {
                $errDesc = "A user is currently logged into this machine"
                $runCode = 10
            }
        }
    }
    

    ## Get Model - RUNCODE 2
    If($runCode -eq 0){
        $model = (gwmi win32_computersystem -ComputerName $workstation).Model.trim()
        If($model -eq "" -OR $model -eq $NULL){
            $runCode = 2
            $errDesc = "No Model Returned"
            If($verbose){
                Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
        }
    }
    <#
    ## Check for Laptops - RUNCODE 3
    If($runCode -eq 0){
        If($model -like "*Latitude*"){
            $runCode = 3
            $errDesc = "Not Patching Laptops"
            Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
        }
    }
    #>

    ## Check for VMs - RUNCODE 11
    If($runCode -eq 0){
        If($model -like "*Virtual*"){
            $runCode = 3
            $errDesc = "Not Patching VMs"
            If($verbose){
                Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
        }
    }

    ## Get Latest Bios Version - RUNCODE 4
    If($runCode -eq 0){
        $latestVersion = $biosVersions[$model].Split(';')[0]
        $fileName = $biosVersions[$model].Split(';')[1]
        If($latestVersion -eq "" -OR $latestVersion -eq $NULL){
            $runCode = 4
            $errDesc = "No BIOS Listed for Model"
            If($verbose){
                Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
        }
    }

    If(-Not $Verify){
        ## Verify BIOS Version - RUNCODE 5
        If($runCode -eq 0){
            $currentVersion = (gwmi win32_bios -ComputerName $workstation).SMBIOSBIOSVersion.trim()
            If($currentVersion -eq $latestVersion){
                $runCode = 5
                $errDesc = "BIOS Already Updated"
                If($verbose){
                    Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
                }
            }
        }
    

        ## Get fileName - RUNCODE 6
        If($runCode -eq 0){
            #$fileName = $fileNames[$latestVersion]
            If($fileName -eq "" -OR $fileName -eq $NULL){
                $runCode = 6
                $errDesc = "No Filename Listed for BIOS"
                If($verbose){
                    Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
                }
            }else{
                $errDesc = "No Error. Moving to Upgrading"
                If($verbose){
                    Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
                }
                $errDesc
            }
        }
    }

    If(-Not $Verify){
        ## Create Directory - RUNCODE 7
        If($runCode -eq 0){
            If(-not (Test-Path "\\$workstation\c$\Dell")){
                New-Item -ItemType Directory -Name "Dell" -Path "\\$workstation\c$\"
                If(-not (Test-Path "\\$workstation\c$\Dell")){
                    $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
                    $errDesc = "Dell Folder Creation Failed"
                    If($verbose){
                        Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
                    }
                    $runCode = 7
                }
            }
        }

        ## Copy File - RUNCODE 8
        If($runCode -eq 0){
            If(-not (Test-Path "\\$workstation\c$\Dell\$fileName")){
                $toPath = "\\$workstation\c$\Dell\$fileName"
                $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
                Write-Host "Start Copy ; $dt"
                Copy-Item -Path "$fromPath\$fileName" -Destination "$toPath"
                $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
                Write-Host "End Copy ; $dt"
                If(-not (Test-Path "\\$workstation\c$\Dell\$fileName")){
                            $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
                            $errDesc = "BIOS Installer Copy Failed"
                            Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
                            $runCode = 8
                }
            }
        }

        
        If(-not $verify){
            ## Verify No One is Logged On - RUNCODE 10
            $user = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $workstation | Select Username).username
            If( $user -ne $NULL -AND $user -ne "")
            {
                $errDesc = "A user is currently logged into this machine"
                $runCode = 10
            }
        }
        
        
        If(-not $CopyOnly){                   
            ## Run Update - RUNCODE 9
            If($runCode -eq 0){
                Write-Host "RUNNING UPDATE"
                $s = New-PSSession -ComputerName $workstation
                Switch($model){
                    "OptiPlex 3060" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_3060_1.4.2.exe /s /r}; break}
                    "OptiPlex 780" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\O780-A15.exe /s /r}; break}
                    "OptiPlex 3020M" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_3020M_A15.exe /s /r}; break}
                    "OptiPlex 3050" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_3050_1.12.1.exe /s /r}; break}
                    "OptiPlex 3040" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_3040_1.11.3.exe /s /r}; break}
                    "OptiPlex 5050" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_5050_1.12.1.exe /s /r}; break}
                    "OptiPlex 7010" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\O7010A29.exe /s /r}; break}
                    "PowerEdge R230" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_DJ7XK_WN64_2.7.1.EXE /s /r}; break}
                    "PowerEdge R320" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_7GHMX_WN64_2.7.0.EXE /s /r}; break}
                    "PowerEdge R410" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_XXNW5_WN64_1.14.0_01.EXE /s /r}; break}
                    "PowerEdge R510" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_PYCXX_WN64_1.14.0_01.EXE /s /r}; break}
                    "PowerEdge R520" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_3X8FN_WN64_2.7.0.EXE /s /r}; break}
                    "PowerEdge R530" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_VH9R0_WN64_2.10.5.EXE /s /r}; break}
                    "PowerEdge R710" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_0F4YY_WN64_6.6.0_01.EXE /s /r}; break}
                    "PowerEdge R240" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\BIOS_HT9C7_WN64_2.1.6.EXE /s /r}; break}
                    "Latitude 5580" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\Latitude_5X80_Precision_3520_1.16.0.exe /s /r /bls}; break}
                    "Latitude 5590" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\Latitude_5X90_1.10.1.exe /s /r /bls}; break}
                    "Latitude E5570" {Write-Host "Initiating";Invoke-Command -Session $s -ScriptBlock { C:\Dell\Latitude_E5x70_Precision_3510_1.21.4.exe /s /r /bls}; break}          
                    default { Write-Host "Skipped"; break}
                }
                Sleep 45
                #Invoke-Command -Session $s -ScriptBlock { param([string]$fileName) & "C:\Dell\$fileName /s /r"} -ArgumentList $fileName
                Remove-PSSession $s
            }
        }
    }    

    ## Verify Update - RUNCODE 5
    If($verify){
        If($runCode -eq 0){
            $currentVersion = (gwmi win32_bios -ComputerName $workstation).SMBIOSBIOSVersion.trim()            
            If($currentVersion -eq $latestVersion){
                $runCode = 5
                $errDesc = "BIOS is up to date"
                #Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
            If($verbose){
                Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
        }else{
            If($verbose){
                Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
            }
        }
        If($verbose){
            Write-Host "$workstation ; $model ; $currentVersion ; $latestVersion ; $fileName ; $errDesc"
        }
    }
    $count = $count + 1
    If($runCode -eq 0){
        $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
        Write-Output "$count ; $dt ; $workstation ; Script completed successfully. $runCode" | tee .\$fn -Append
    }elseif($runCode -eq 5){
        $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
        Write-Output "$count ; $dt ; $workstation ; $errDesc" | tee .\$fn -Append
    }else{
        $dt = Get-Date -Format yyyyMMdd-HH:mm:ss
        Write-Output "$count ; $dt ; $workstation ; Script failed to complete ; $errDesc ; $runCode" | tee .\$fn -Append
    }
    
    If(-not $Verify){
        
    }
    If($verbose){
        ""
    }
}

<#
$s = New-PSSession -ComputerName 
Invoke-Command -Session $s -ScriptBlock { C:\Dell\OptiPlex_3060_1.4.2.exe /s /r}
Remove-PSSession $s
#>
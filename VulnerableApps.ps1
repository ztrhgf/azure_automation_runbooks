<#
    Azure Automation script for notifying users vulnerable software found on their devices
    More info at TODO

    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    !!! Modify variables in 'CORE variables' region before running this code !!!
    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    Required WindowsDefenderATP permissions:
        User.Read.All
        SecurityRecommendation.Read.All
        Alert.Read.All
        Software.Read.All
        Vulnerability.Read.All
        Machine.Read.All
        AdvancedQuery.Read.All

    Required other permissions:
        'Key Vault Secrets User' IAM role to read SendGrid token saved in KeyVault
        'Storage Account Contributor' IAM role over Storage Account container where script data are stored

    Required PSH modules:
        AzureResourceStuff
        M365DefenderStuff
        CommonStuff
        PSSendGrid
#>

# set to $true to get overview about what would be done without really do any changes
$WHATIF = $false

$ErrorActionPreference = "Stop"

Import-Module PSSendGrid, CommonStuff, M365DefenderStuff, AzureResourceStuff

#region authentication
$null = Connect-AzAccount -Identity

$header = New-M365DefenderAuthHeader -identity
#endregion authentication

#region CORE variables
# what is the minimum severity vulnerability level you want to notify about
$vulnerabilitySeverity = "Critical" # possible values are: Low, Medium, High, Critical
# name of the xml file where persistent helper data will be stored
$persistentVariableName = "vulnerableAppsAPS_previouslyProcessed"
# what is the employees email domain (notification email will be send to "<accountName>@<emailDomain>")
$emailDomain = "contoso.com"
# who should be in the copy of the second notification email (security team, manager, ...)
$secondEmailCopyTo = "security@$emailDomain"
# to who send email when potencial issues with this script occurs
$warningEmailTo = "it@$emailDomain"
# how long does it take before first notification email should be send after vuln. detection
$sendEmailAfter = 30
# how long does it take before second email should be send after the first one
$sendSecondEmailAfter = 14
# default parameters for Send-EmailViaSendGrid
$sendGridParam = @{
    from = "vulnScan@$emailDomain"
    asHTML = $true
    vaultSubscription = 'production'
    vaultName = 'secrets'
    secretName = 'sendgrid'
}

#region list of apps where notification should be sent right away
# list of apps where notification email should be sent right away (don't apply $sendEmailAfter wait time)
# - names has to be extracted from $vulnerabilityPerMachine.vulnsw or Get-M365DefenderSoftware ('Name' property)
# $appToImmediateNotify = "visual_studio_", "python", ".net"
$appToImmediateNotify = @()
$appToImmediateNotifyRegex = ($appToImmediateNotify | ? { $_ } | % { [regex]::Escape($_) }) -join "|"
#endregion list of apps where notification should be sent right away

#region list of excluded apps
# matching vulnerability will be skipped from processing and deleted from $previouslyProcessed

<#
- 'CveId' and/or 'ProductName' property/ies (string) have to be defined
- 'ProductVersion' (string) is optional
    - property values can be extracted from $vulnerabilityPerMachine.vulnswdata
- 'ValidUntil' (datetime) is optional (since this date, exclustion will be ignored)
    - BEWARE that in Azure pipeline EN date has to be used a.k.a. month.day.year!!!

example:
[PSCustomObject]@{
    CveId = 'CVE-2024-32002'
    ProductName = 'visual_studio_2022'
    ProductVersion = '17.0.4.0'
    ValidUntil = (Get-Date 10.25.2024) # M.d.yyyy
},
[PSCustomObject]@{
    CveId = 'CVE-2023-20002'
    ProductName = 'visual_studio_2022'
}
#>

# array of objects defining excluded apps
$exclusionList = @()
#endregion list of excluded apps
#endregion CORE variables

# hash with helper data
$previouslyProcessed = Import-VariableFromStorage -fileName $persistentVariableName

if (!$previouslyProcessed) {
    # first run
    $previouslyProcessed = @{}
}

#region internal functions
function _shouldBeSkipped {
    param ($vulnSWData)

    if (!$exclusionList) {
        return $false
    }

    #region input object property check
    if ($vulnSWData.gettype().name -eq 'Hashtable') {
        $propertyNameList = $vulnSWData.Keys
    } elseif ($vulnSWData.gettype().name -eq 'PSCustomObject') {
        $propertyNameList = $vulnSWData | Get-Member -MemberType NoteProperty, Property | select -ExpandProperty Name
    } else {
        throw "Undefined object type $($vulnSWData.gettype().name)"
    }

    if ('CveId' -notin $propertyNameList -or 'ProductName' -notin $propertyNameList -or 'ProductVersion' -notin $propertyNameList) {
        throw "`$vulnSWData is missing some required properties"
    }
    #endregion input object property check

    foreach ($exclusion in $exclusionList) {
        $cveId = $exclusion.CveId
        $productName = $exclusion.ProductName
        $productVersion = $exclusion.ProductVersion
        $validUntil = $exclusion.ValidUntil

        if (!$cveId -and !$productName) {
            throw "CveId or ProductName has to be defined in `$exclusionList"
        }

        if ($validUntil -and [datetime]::now -gt $validUntil) {
            # exclusion isn't valid anymore
            continue
        }

        $vulnSWData2 = $vulnSWData

        if ($cveId) {
            $vulnSWData2 = $vulnSWData2 | ? { $_.cveId -contains $cveId }
        }
        if ($productName) {
            $vulnSWData2 = $vulnSWData2 | ? { $_.productName -eq $productName }
        }
        if ($productVersion) {
            $vulnSWData2 = $vulnSWData2 | ? { $_.productVersion -eq $productVersion }
        }

        if ($vulnSWData2) {
            # matches exclusion rule, should be excluded
            return $true
        }
    }

    return $false
}

function _wasProcessed {
    param ($machineId, $swNameVersion)

    $firstSeenOn = $previouslyProcessed.$machineId.$swNameVersion.firstSeenOn
    if ($firstSeenOn) {
        return $firstSeenOn
    } else {
        return $false
    }
}

function _notificationSent {
    param ($machineId, $swNameVersion)

    $notificationSentOn = $previouslyProcessed.$machineId.$swNameVersion.notificationSentOn
    if ($notificationSentOn) {
        return $notificationSentOn
    } else {
        return $false
    }
}

function _secondNotificationSent {
    param ($machineId, $swNameVersion)

    $notificationSentOn = $previouslyProcessed.$machineId.$swNameVersion.secondNotificationSentOn
    if ($notificationSentOn) {
        return $notificationSentOn
    } else {
        return $false
    }
}

function _generateVulnSWText {
    param (
        [Parameter(Mandatory = $true)]
        $vulnData
    )

    $vulnSWText = ""

    $vulnData | % {
        $appName = $_.productName
        $appVersion = $_.productVersion
        $productVendor = $_.productVendor
        $cveId = $_.cveId
        $deviceId = $_.machineId
        $diskPaths = $null
        $registryPaths = $null

        $CVEHtml = ""
        if ($cveId) {
            $CVEHtml += "CVE: "
            $CVESubHtml = ""
            $cveId | % {
                if ($CVESubHtml) {
                    $CVESubHtml += ", "
                }
                $CVESubHtml += "<a href=`"https://nvd.nist.gov/vuln/detail/$_`">$_</a>"
            }

            $CVEHtml += $CVESubHtml
        }

        $vulnSWText += "<br><br>App name: $appName<br>App version: $appVersion<br>Vendor: $productVendor<br>$CVEHtml"

        #region add how the app was discovered
        $swEvidenceResult = Invoke-M365DefenderSoftwareEvidenceQuery -header $header -appName $appName -appVersion $appVersion -deviceId $deviceId

        if ($swEvidenceResult) {
            if ($diskPaths = $swEvidenceResult.DiskPaths | select -Unique) {
                $vulnSWText += "<br>App detected via disk path(s): $($diskPaths -join ', ')"
            }

            if (!$diskPaths -and ($registryPaths = $swEvidenceResult.RegistryPaths | select -Unique)) {
                $vulnSWText += "<br>App detected via registry path(s): $($registryPaths -join ', ')"
            }
        }
        #endregion add how the app was discovered

        #region add what is the official fix recommendation
        $swRecommendation = Get-M365DefenderRecommendation -header $header -productName $appName | ? { $_.recommendedVersion -and $_.remediationType -eq "Update" } | select -Last 1

        if ($swRecommendation) {
            $vulnSWText += "<br>Microsoft recommendation: $($swRecommendation.recommendationName)"
        }
        #endregion add what is the official fix recommendation
    }

    return $vulnSWText
}
#endregion internal functions

#region remove excluded items from $previouslyProcessed
if ($exclusionList) {
    "`n### Removing excluded items from `$previouslyProcessed"

    $($previouslyProcessed.Clone()).GetEnumerator() | % {
        $machineId = $_.key
        "`tProcessing $machineId"
        $($_.Value.Clone()).GetEnumerator() | % {
            $hashtable = $_
            $vulnSWHash = $hashtable.value
            $shouldBeSkipped = _shouldBeSkipped $vulnSWHash

            if ($shouldBeSkipped) {
                "`t`t- removing $machineId.'$($hashtable.key)'"
                $previouslyProcessed.$machineId.remove($hashtable.key)
            }
        }
    }

    if (!$WHATIF) {
        Export-VariableToStorage -value $previouslyProcessed -fileName $persistentVariableName
    }
}
#endregion remove excluded items from $previouslyProcessed

#region process found vulnerabilities
$vulnerabilityPerMachine = Get-M365DefenderVulnerabilityReport -groupBy machine -header $header -skipOSVuln -severity $vulnerabilitySeverity

# machine IDs where email about found vulnerability should be send, but owner is missing
# probably pre-provisioned but not handed over machines
$vulnMachineWithoutOwner = @()

foreach ($machineVulnerability in $vulnerabilityPerMachine) {
    $machineId = $machineVulnerability.MachineId
    $computerName = $machineVulnerability.ComputerName
    $vulnEmailData = @()
    $vulnEmailSecondStageData = @()

    "`n### Processing $computerName ($machineId)"

    foreach ($vulnSW in $machineVulnerability.VulnSWData) {
        $vulnSWName = $vulnSW.productName
        $vulnSWVersion = $vulnSW.productVersion
        $cveId = $vulnSW.cveId
        $vulnSWNameVersion = $vulnSW.VulnSW
        $wasProcessed = _wasProcessed -machineId $machineId -swNameVersion $vulnSWNameVersion
        $shouldBeSkipped = _shouldBeSkipped $vulnSW

        "`t- $vulnSWName ($vulnSWVersion, $cveId)"

        if ($shouldBeSkipped) {
            "`t`t- skipping, is in exclusion list"
            continue
        }

        if ($appToImmediateNotifyRegex -and ($vulnSWName -match $appToImmediateNotifyRegex)) {
            # it is software where notification should be send immediatelly
            # because software isn't automatically updated etc

            "`t`t- app isn't automatically updated (no wait time before sending notification)"

            if ($wasProcessed) {
                # this vulnerability on this machine was already processed

                "`t`t- was already processed"

                $notificationSent = _notificationSent -machineId $machineId -swNameVersion $vulnSWNameVersion
                $secondNotificationSent = _secondNotificationSent -machineId $machineId -swNameVersion $vulnSWNameVersion

                if ($notificationSent) {
                    # first notification email was already sent to the machine user(s)

                    if ($notificationSent -lt [datetime]::Now.AddDays(-$sendSecondEmailAfter) -and !$secondNotificationSent) {
                        # second notification email should be send
                        "`t`t- second notification should be sent"
                        $vulnEmailSecondStageData += $vulnSW | select *, @{n = 'machineId'; e = { $machineId } }
                    } else {
                        # there is no need to warn user again (yet), threshold wasn't hit yet
                        "`t`t- second notification should NOT be sent yet"
                    }
                } else {
                    # no notification email was sent to the machine user(s)
                    # this shouldn't happen, because email should be sent right away

                    $vulnEmailData += $vulnSW | select *, @{n = 'machineId'; e = { $machineId } }

                    # make a note about processing this vulnerable software
                    $vulnSWHash = @{
                        cveId                    = $cveId
                        firstSeenOn              = [datetime]::Now
                        notificationSentOn       = $null
                        computerName             = $computerName
                        secondNotificationSentOn = $null
                        productName              = $vulnSWName
                        productVersion           = $vulnSWVersion
                        productVendor            = $vulnSW.productVendor
                    }
                    if ($previouslyProcessed.$machineId) {
                        $previouslyProcessed.$machineId.$vulnSWNameVersion = $vulnSWHash
                    } else {
                        $previouslyProcessed.$machineId = @{
                            $vulnSWNameVersion = $vulnSWHash
                        }
                    }
                }
            } else {
                # this vulnerability on this machine wasn't processed yet

                "`t`t- wasn't yet processed"

                # send notification email right away
                $vulnEmailData += $vulnSW | select *, @{n = 'machineId'; e = { $machineId } }

                # make a note about processing this vulnerable software
                $vulnSWHash = @{
                    cveId                    = $cveId
                    firstSeenOn              = [datetime]::Now
                    notificationSentOn       = $null
                    computerName             = $computerName
                    secondNotificationSentOn = $null
                    productName              = $vulnSWName
                    productVersion           = $vulnSWVersion
                    productVendor            = $vulnSW.productVendor
                }
                if ($previouslyProcessed.$machineId) {
                    $previouslyProcessed.$machineId.$vulnSWNameVersion = $vulnSWHash
                } else {
                    $previouslyProcessed.$machineId = @{
                        $vulnSWNameVersion = $vulnSWHash
                    }
                }
            }
        } else {
            # it is software, where notification should be sent after defined time

            "`t`t- app is automatically updated a.k.a. notification should be sent after specified wait time"

            if ($wasProcessed) {
                # this vulnerability on this machine was already processed

                "`t`t- was already processed"

                $notificationSent = _notificationSent -machineId $machineId -swNameVersion $vulnSWNameVersion
                $secondNotificationSent = _secondNotificationSent -machineId $machineId -swNameVersion $vulnSWNameVersion

                if ($notificationSent) {
                    # first notification email was already sent to the machine user(s)

                    if ($notificationSent -lt [datetime]::Now.AddDays(-$sendSecondEmailAfter) -and !$secondNotificationSent) {
                        # second notification email should be send
                        "`t`t- second notification should be sent"
                        $vulnEmailSecondStageData += $vulnSW | select *, @{n = 'machineId'; e = { $machineId } }
                    } else {
                        # there is no need to warn user again (yet), threshold wasn't hit yet
                        "`t`t- second notification should NOT be sent yet"
                    }
                } else {
                    # no notification email was sent to the machine user(s)
                    if ($wasProcessed -lt [datetime]::Now.AddDays(-$sendEmailAfter)) {
                        # this vulnerability was seen more than $sendEmailAfter days ago
                        # its above threshold, user(s) will be notified
                        "`t`t- first notification should be sent"
                        $vulnEmailData += $vulnSW | select *, @{n = 'machineId'; e = { $machineId } }
                    } else {
                        # there is no need to warn user again (yet), threshold wasn't hit yet
                        "`t`t- first notification should NOT be sent yet"
                    }
                }
            } else {
                # this vulnerability on this machine wasn't processed yet

                "`t`t- wasn't yet processed"

                # make a note about processing this vulnerable software
                $vulnSWHash = @{
                    cveId                    = $vulnSW.cveId
                    firstSeenOn              = [datetime]::Now
                    notificationSentOn       = $null
                    computerName             = $computerName
                    secondNotificationSentOn = $null
                    productName              = $vulnSW.productName
                    productVersion           = $vulnSW.productVersion
                    productVendor            = $vulnSW.productVendor
                }
                if ($previouslyProcessed.$machineId) {
                    $previouslyProcessed.$machineId.$vulnSWNameVersion = $vulnSWHash
                } else {
                    $previouslyProcessed.$machineId = @{
                        $vulnSWNameVersion = $vulnSWHash
                    }
                }
            }
        }
    }

    #region notify user(s)
    if ($vulnEmailData -or $vulnEmailSecondStageData) {
        # to minimize throttling, get computer owner only if necessary
        $user = Get-M365DefenderMachineUser -header $header -machineId $machineId | ? { $_.logonTypes -like '*Interactive*' -and $_.accountName -ne "administrator" }
    }

    if ($vulnEmailData) {
        # sending first notification email

        if ($user) {
            $to = $user | % { $_.accountName + "@$emailDomain" }
        } else {
            "`t`t- skipping, doesn't have an owner"
            $vulnMachineWithoutOwner += $machineId
            continue
        }

        $vulnSWText = _generateVulnSWText $vulnEmailData

        $body = "Hi,<br>on your device '$computerName' were found some software with critical vulnerability. Please update/uninstall it:$vulnSWText<br><br>You've got a $sendSecondEmailAfter-day window to take care of this issue. Once that's done, we'll give your device another check. Thanks for your cooperation!<br><br>Sincerely your IT"

        "Sending email to $to about: $($vulnEmailData.VulnSW -join ", ") text:`n$body"

        if (!$vulnSWText) {
            throw "no data to sent, this shouldn't happen!"
        }

        if (!$WHATIF) {
            Send-EmailViaSendGrid -to $to -subject "Vulnerable software was found on your device $computerName" -body $body @sendGridParam
        }

        # make a note about sending the email
        foreach ($swNameVersion in $vulnEmailData.VulnSW) {
            $previouslyProcessed.$machineId.$swNameVersion.notificationSentOn = [datetime]::Now
        }

        if (!$WHATIF) {
            # save in case some error is thrown
            Export-VariableToStorage -value $previouslyProcessed -fileName $persistentVariableName
        }
    }

    if ($vulnEmailSecondStageData) {
        # sending second notification email

        if ($user) {
            $to = $user | % { $_.accountName + "@$emailDomain" }
        } else {
            "`t`t- skipping, doesn't have an owner"
            $vulnMachineWithoutOwner += $machineId
            continue
        }

        [array] $to += $secondEmailCopyTo

        $vulnSWText = _generateVulnSWText $vulnEmailSecondStageData

        $body = "Hi,<br>on your device is still installed some vulnerable software. Please update/uninstall it:$vulnSWText<br><br>You were notified about this issue $sendSecondEmailAfter days ago.<br><br>Sincerely your IT"

        "Sending second email to $to about: $($vulnEmailSecondStageData.VulnSW -join ", ") text:`n$body"

        if (!$vulnSWText) {
            throw "no data to sent, this shouldn't happen!"
        }

        if (!$WHATIF) {
            Send-EmailViaSendGrid -to $to -subject "Your device $computerName still has vulnerable SW on it" -body $body @sendGridParam
        }

        # make a not about sending the email
        foreach ($swNameVersion in $vulnEmailSecondStageData.VulnSW) {
            $previouslyProcessed.$machineId.$swNameVersion.secondNotificationSentOn = [datetime]::Now
        }

        if (!$WHATIF) {
            # save in case some error is thrown
            Export-VariableToStorage -value $previouslyProcessed -fileName $persistentVariableName
        }
    }
    #endregion notify user(s)
}
#endregion process found vulnerabilities

#region cleanup stale vulnerabilities records
if ($previouslyProcessed) {
    #remove machines without any vulnerable SW
    $cleanMachineId = $previouslyProcessed.Keys | ? { $_ -notin $vulnerabilityPerMachine.machineId }
    $cleanMachineId | ? { $_ } | % {
        $computerName = $previouslyProcessed.$_.Values.ComputerName | select -Unique
        "Removing all vuln. records for machine $computerName ($_). It is clean now."
        if (!$WHATIF) {
            $previouslyProcessed.Remove($_)
        }
    }

    # remove machines without any owner (probably pre-provisioned but not handed over)
    if ($vulnMachineWithoutOwner) {
        $vulnMachineWithoutOwner | % {
            $computerName = $previouslyProcessed.$_.Values.ComputerName | select -Unique
            "Removing all vuln. records for machine $computerName ($_). It doesn't have any owner."
            if (!$WHATIF) {
                $previouslyProcessed.Remove($_)
            }
        }

        # warn IT in case suspicious number of vulnerable machines doesn't have an owner
        # it probably means that there is a problem with getting the owners (insufficient permissions?)
        if ((@($vulnMachineWithoutOwner) | select -Unique).count -ge ($previouslyProcessed.Keys.count * 0.1)) {
            $to = $warningEmailTo
            $body = "Hi,<br>VulnerableAppsAPS automation found a lot of ($((@($vulnMachineWithoutOwner) | select -Unique).count)) machines with vulnerable software, but without any owner. This is suspicious and probably means that there is problem with receiving machine owner<br><br>Solve it :P"

            "Sending email to $to about: too many machines without owner was found text:`n$body"

            if (!$WHATIF) {
                Send-EmailViaSendGrid -to $to -subject "Too many machines with vulnerable software but without owner was found" -body $body @sendGridParam
            }
        }
    }

    # remove vuln records that was not found during this check
    $previouslyProcessed.GetEnumerator() | % {
        $processedSWHash = $_
        $machineId = $processedSWHash.Key
        $vulnSWNameVersionList = $processedSWHash.Value.Keys
        $computerName = $processedSWHash.Value.Values.ComputerName | select -Unique

        $actualMachineVulnerability = $vulnerabilityPerMachine | ? MachineId -EQ $machineId

        $fixedVulnSW = $vulnSWNameVersionList | ? { $_ -notin $actualMachineVulnerability.VulnSW }

        $fixedVulnSW | % {
            "Removing '$_' record for machine $computerName ($machineId). Issue was fixed."
            if (!$WHATIF) {
                $processedSWHash.Value.Remove($_)
            }
        }
    }

    # save
    if (!$WHATIF) {
        Export-VariableToStorage -value $previouslyProcessed -fileName $persistentVariableName
    }
}
#endregion cleanup stale vulnerabilities records

# final save
if (!$WHATIF) {
    Export-VariableToStorage -value $previouslyProcessed -fileName $persistentVariableName
}

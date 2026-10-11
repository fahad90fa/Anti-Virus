// Fileless / script-abuse indicators. These match the textual artifacts of
// living-off-the-land and in-memory execution. The behavioral script-intent
// analyzer is the primary defense here; these static rules are a fast first pass.

rule Powershell_Encoded_Command : fileless lolbin {
    meta:
        description = "PowerShell encoded-command / download-cradle markers"
        severity    = "high"
        weight      = 0.55
    strings:
        $enc  = "-EncodedCommand" nocase
        $enc2 = "-enc" nocase
        $frombase = "FromBase64String" nocase
        $iex  = "IEX" nocase
        $invoke = "Invoke-Expression" nocase
        $dl   = "DownloadString" nocase
    condition:
        ($enc or $enc2 or $frombase) and ($iex or $invoke or $dl)
}

rule Amsi_Bypass_Attempt : evasion fileless {
    meta:
        description = "In-memory AMSI bypass markers"
        severity    = "high"
        weight      = 0.6
    strings:
        $a = "amsiInitFailed" nocase
        $b = "AmsiScanBuffer" nocase
        $c = "System.Management.Automation.AmsiUtils" nocase
    condition:
        any of them
}

rule Lolbin_Abuse : lolbin {
    meta:
        description = "Suspicious living-off-the-land binary invocation"
        severity    = "medium"
        weight      = 0.35
    strings:
        $mshta = "mshta" nocase
        $rundll = "rundll32" nocase
        $regsvr = "regsvr32" nocase
        $certutil = "certutil" nocase
        $bits = "bitsadmin" nocase
    condition:
        any of them
}

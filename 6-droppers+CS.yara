rule Windows_Trojan_CobaltStrike_c851687a {
    meta:
        author = "Elastic Security"
        id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
        fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC Bypass module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
    condition:
        2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e {
    meta:
        author = "Elastic Security"
        id = "0b58325e-2538-434d-9a2c-26e2c32db039"
        fingerprint = "8ecd5bdce925ae5d4f90cecb9bc8c3901b54ba1c899a33354bcf529eeb2485d4"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Keylogger module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "keylogger.dll" ascii fullword
        $a2 = "keylogger.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\keylogger" ascii fullword
        $a4 = "%cE=======%c" ascii fullword
        $a5 = "[unknown: %02X]" ascii fullword
        $b1 = "ReflectiveLoader"
        $b2 = "%c2%s%c" ascii fullword
        $b3 = "[numlock]" ascii fullword
        $b4 = "%cC%s" ascii fullword
        $b5 = "[backspace]" ascii fullword
        $b6 = "[scroll lock]" ascii fullword
        $b7 = "[control]" ascii fullword
        $b8 = "[left]" ascii fullword
        $b9 = "[page up]" ascii fullword
        $b10 = "[page down]" ascii fullword
        $b11 = "[prtscr]" ascii fullword
        $b12 = "ZRich9" ascii fullword
        $b13 = "[ctrl]" ascii fullword
        $b14 = "[home]" ascii fullword
        $b15 = "[pause]" ascii fullword
        $b16 = "[clear]" ascii fullword
    condition:
        1 of ($a*) and 14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 {
    meta:
        author = "Elastic Security"
        id = "2b8cddf8-ca7a-4f85-be9d-6d8534d0482e"
        fingerprint = "0d7d28d79004ca61b0cfdcda29bd95e3333e6fc6e6646a3f6ba058aa01bee188"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies dll load module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
        $b1 = "__imp_BeaconErrorDD" ascii fullword
        $b2 = "__imp_BeaconErrorNA" ascii fullword
        $b3 = "__imp_BeaconErrorD" ascii fullword
        $b4 = "__imp_BeaconDataInt" ascii fullword
        $b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
        $b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
        $b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
        $b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
        $c1 = "__imp__BeaconErrorDD" ascii fullword
        $c2 = "__imp__BeaconErrorNA" ascii fullword
        $c3 = "__imp__BeaconErrorD" ascii fullword
        $c4 = "__imp__BeaconDataInt" ascii fullword
        $c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
        $c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
        $c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
        $c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767 {
    meta:
        author = "Elastic Security"
        id = "59b44767-c9a5-42c0-b177-7fe49afd7dfb"
        fingerprint = "882886a282ec78623a0d3096be3d324a8a1b8a23bcb88ea0548df2fae5e27aa5"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies getsystem module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
        $b1 = "getsystem failed." ascii fullword
        $b2 = "_isSystemSID" ascii fullword
        $b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
        $c1 = "getsystem failed." ascii fullword
        $c2 = "$pdata$isSystemSID" ascii fullword
        $c3 = "$unwind$isSystemSID" ascii fullword
        $c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f {
    meta:
        author = "Elastic Security"
        id = "7efd3c3f-1104-4b46-9d1e-dc2c62381b8c"
        fingerprint = "9e7c7c9a7436f5ee4c27fd46d6f06e7c88f4e4d1166759573cedc3ed666e1838"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Hashdump module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 70
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "hashdump.dll" ascii fullword
        $a2 = "hashdump.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\hashdump" ascii fullword
        $a4 = "ReflectiveLoader"
        $a5 = "Global\\SAM" ascii fullword
        $a6 = "Global\\FREE" ascii fullword
        $a7 = "[-] no results." ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_CobaltStrike_6e971281 {
    meta:
        author = "Elastic Security"
        id = "6e971281-3ee3-402f-8a72-745ec8fb91fb"
        fingerprint = "62d97cf73618a1b4d773d5494b2761714be53d5cda774f9a96eaa512c8d5da12"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Interfaces module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
        $b1 = "__imp_BeaconFormatAlloc" ascii fullword
        $b2 = "__imp_BeaconFormatPrintf" ascii fullword
        $b3 = "__imp_BeaconOutput" ascii fullword
        $b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
        $b5 = "__imp_KERNEL32$LocalFree" ascii fullword
        $b6 = "__imp_LoadLibraryA" ascii fullword
        $c1 = "__imp__BeaconFormatAlloc" ascii fullword
        $c2 = "__imp__BeaconFormatPrintf" ascii fullword
        $c3 = "__imp__BeaconOutput" ascii fullword
        $c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
        $c5 = "__imp__KERNEL32$LocalFree" ascii fullword
        $c6 = "__imp__LoadLibraryA" ascii fullword
    condition:
        1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_09b79efa {
    meta:
        author = "Elastic Security"
        id = "09b79efa-55d7-481d-9ee0-74ac5f787cef"
        fingerprint = "04ef6555e8668c56c528dc62184331a6562f47652c73de732e5f7c82779f2fd8"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Invoke Assembly module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "invokeassembly.x64.dll" ascii fullword
        $a2 = "invokeassembly.dll" ascii fullword
        $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $b3 = "[-] Failed to create the runtime host" ascii fullword
        $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $b6 = "ReflectiveLoader"
        $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $b8 = "[-] No .NET runtime found. :(" ascii fullword
        $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
    condition:
        1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e {
    meta:
        author = "Elastic Security"
        id = "6e77233e-7fb4-4295-823d-f97786c5d9c4"
        fingerprint = "cef2949eae78b1c321c2ec4010749a5ac0551d680bd5eb85493fc88c5227d285"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Kerberos module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
        $a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
        $a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
        $a4 = "command_kerberos_ticket_use" ascii fullword
        $a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
        $a6 = "command_kerberos_ticket_purge" ascii fullword
        $a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
        $a8 = "$unwind$kerberos_init" ascii fullword
        $a9 = "$unwind$KerberosTicketUse" ascii fullword
        $a10 = "KerberosTicketUse" ascii fullword
        $a11 = "$unwind$KerberosTicketPurge" ascii fullword
        $b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
        $b2 = "_command_kerberos_ticket_use" ascii fullword
        $b3 = "_command_kerberos_ticket_purge" ascii fullword
        $b4 = "_kerberos_init" ascii fullword
        $b5 = "_KerberosTicketUse" ascii fullword
        $b6 = "_KerberosTicketPurge" ascii fullword
        $b7 = "_LsaCallKerberosPackage" ascii fullword
    condition:
        5 of ($a*) or 3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a {
    meta:
        author = "Elastic Security"
        id = "de42495a-0002-466e-98b9-19c9ebb9240e"
        fingerprint = "dab3c25809ec3af70df5a8a04a2efd4e8ecb13a4c87001ea699e7a1512973b82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Mimikatz module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
        $b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
        $b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
        $b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
        $b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
        $b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
        $b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
        $b7 = "mimikatz(powershell) # %s" wide fullword
        $b8 = "powershell_reflective_mimikatz" ascii fullword
        $b9 = "mimikatz_dpapi_cache.ndr" wide fullword
        $b10 = "mimikatz.log" wide fullword
        $b11 = "ERROR mimikatz_doLocal" wide
        $b12 = "mimikatz_x64.compressed" wide
    condition:
        1 of ($a*) and 7 of ($b*)
}

rule Windows_Trojan_CobaltStrike_72f68375 {
    meta:
        author = "Elastic Security"
        id = "72f68375-35ab-49cc-905d-15302389a236"
        fingerprint = "ecc28f414b2c347722b681589da8529c6f3af0491845453874f8fd87c2ae86d7"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netdomain module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
        $b1 = "__imp_BeaconPrintf" ascii fullword
        $b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
        $b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
        $c1 = "__imp__BeaconPrintf" ascii fullword
        $c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
        $c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb {
    meta:
        author = "Elastic Security"
        id = "15f680fb-a04f-472d-a182-0b9bee111351"
        fingerprint = "0ecb8e41c01bf97d6dea4cf6456b769c6dd2a037b37d754f38580bcf561e1d2c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Netview module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "netview.x64.dll" ascii fullword
        $a2 = "netview.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\netview" ascii fullword
        $b1 = "Sessions for \\\\%s:" ascii fullword
        $b2 = "Account information for %s on \\\\%s:" ascii fullword
        $b3 = "Users for \\\\%s:" ascii fullword
        $b4 = "Shares at \\\\%s:" ascii fullword
        $b5 = "ReflectiveLoader" ascii fullword
        $b6 = "Password changeable" ascii fullword
        $b7 = "User's Comment" wide fullword
        $b8 = "List of hosts for domain '%s':" ascii fullword
        $b9 = "Password changeable" ascii fullword
        $b10 = "Logged on users at \\\\%s:" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
    meta:
        author = "Elastic Security"
        id = "5b4383ec-3c93-4e91-850e-d43cc3a86710"
        fingerprint = "283d3d2924e92b31f26ec4fc6b79c51bd652fb1377b6985b003f09f8c3dba66c"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Portscan module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "portscan.x64.dll" ascii fullword
        $a2 = "portscan.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\portscan" ascii fullword
        $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $b2 = "(ARP) Target '%s' is alive. " ascii fullword
        $b3 = "TARGETS!12345" ascii fullword
        $b4 = "ReflectiveLoader" ascii fullword
        $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $b6 = "Scanner module is complete" ascii fullword
        $b7 = "pingpong" ascii fullword
        $b8 = "PORTS!12345" ascii fullword
        $b9 = "%s:%d (%s)" ascii fullword
        $b10 = "PREFERENCES!12345" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
    meta:
        author = "Elastic Security"
        id = "91e08059-46a8-47d0-91c9-e86874951a4a"
        fingerprint = "d8baacb58a3db00489827275ad6a2d007c018eaecbce469356b068d8a758634b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Post Ex module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "postex.x64.dll" ascii fullword
        $a2 = "postex.dll" ascii fullword
        $a3 = "RunAsAdminCMSTP" ascii fullword
        $a4 = "KerberosTicketPurge" ascii fullword
        $b1 = "GetSystem" ascii fullword
        $b2 = "HelloWorld" ascii fullword
        $b3 = "KerberosTicketUse" ascii fullword
        $b4 = "SpawnAsAdmin" ascii fullword
        $b5 = "RunAsAdmin" ascii fullword
        $b6 = "NetDomain" ascii fullword
    condition:
        2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
    meta:
        author = "Elastic Security"
        id = "ee756db7-e177-41f0-af99-c44646d334f7"
        fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561 {
    meta:
        author = "Elastic Security"
        id = "9c0d5561-5b09-44ae-8e8c-336dee606199"
        fingerprint = "01d53fcdb320f0cd468a2521c3e96dcb0b9aa00e7a7a9442069773c6b3759059"
        creation_date = "2021-03-23"
        last_modified = "2021-10-04"
        description = "Identifies PowerShell Runner module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PowerShellRunner.dll" wide fullword
        $a2 = "powershell.x64.dll" ascii fullword
        $a3 = "powershell.dll" ascii fullword
        $a4 = "\\\\.\\pipe\\powershell" ascii fullword
        $b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
        $b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
        $b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
        $b5 = "CustomPSHostUserInterface" ascii fullword
        $b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
        $b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
        $c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
    condition:
        (1 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124 {
    meta:
        author = "Elastic Security"
        id = "59ed9124-bc20-4ea6-b0a7-63ee3359e69c"
        fingerprint = "7823e3b98e55a83bf94b0f07e4c116dbbda35adc09fa0b367f8a978a80c2efff"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies PsExec module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
        $b1 = "__imp_BeaconDataExtract" ascii fullword
        $b2 = "__imp_BeaconDataParse" ascii fullword
        $b3 = "__imp_BeaconDataParse" ascii fullword
        $b4 = "__imp_BeaconDataParse" ascii fullword
        $b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
        $b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
        $b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
        $b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
        $c1 = "__imp__BeaconDataExtract" ascii fullword
        $c2 = "__imp__BeaconDataParse" ascii fullword
        $c3 = "__imp__BeaconDataParse" ascii fullword
        $c4 = "__imp__BeaconDataParse" ascii fullword
        $c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
        $c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
        $c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
        $c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7 {
    meta:
        author = "Elastic Security"
        id = "8a791eb7-dc0c-4150-9e5b-2dc21af0c77d"
        fingerprint = "4967886ba5e663f2e2dc0631939308d7d8f2194a30590a230973e1b91bd625e1"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Registry module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
        $b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
        $b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
        $b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
        $b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
        $b5 = "__imp_BeaconFormatAlloc" ascii fullword
        $b6 = "__imp_BeaconOutput" ascii fullword
        $b7 = "__imp_BeaconFormatFree" ascii fullword
        $b8 = "__imp_BeaconDataPtr" ascii fullword
        $c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
        $c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
        $c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
        $c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
        $c5 = "__imp__BeaconFormatAlloc" ascii fullword
        $c6 = "__imp__BeaconOutput" ascii fullword
        $c7 = "__imp__BeaconFormatFree" ascii fullword
        $c8 = "__imp__BeaconDataPtr" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
    meta:
        author = "Elastic Security"
        id = "d00573a3-db26-4e6b-aabf-7af4a818f383"
        fingerprint = "b6fa0792b99ea55f359858d225685647f54b55caabe53f58b413083b8ad60e79"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Screenshot module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "screenshot.x64.dll" ascii fullword
        $a2 = "screenshot.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $b2 = "GetDesktopWindow" ascii fullword
        $b3 = "CreateCompatibleBitmap" ascii fullword
        $b4 = "GDI32.dll" ascii fullword
        $b5 = "ReflectiveLoader"
        $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
    condition:
        2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c {
    meta:
        author = "Elastic Security"
        id = "7bcd759c-8e3d-4559-9381-1f4fe8b3dd95"
        fingerprint = "553085f1d1ca8dcd797360b287951845753eee7370610a1223c815a200a5ed20"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies SSH Agent module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "sshagent.x64.dll" ascii fullword
        $a2 = "sshagent.dll" ascii fullword
        $b1 = "\\\\.\\pipe\\sshagent" ascii fullword
        $b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_CobaltStrike_a56b820f {
    meta:
        author = "Elastic Security"
        id = "a56b820f-0a20-4054-9c2d-008862646a78"
        fingerprint = "5418e695bcb1c37e72a7ff24a39219dc12b3fe06c29cedefd500c5e82c362b6d"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Timestomp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
        $b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
        $b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
        $b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
        $b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
        $b5 = "__imp_BeaconDataExtract" ascii fullword
        $b6 = "__imp_BeaconPrintf" ascii fullword
        $b7 = "__imp_BeaconDataParse" ascii fullword
        $b8 = "__imp_BeaconDataExtract" ascii fullword
        $c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
        $c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
        $c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
        $c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
        $c5 = "__imp__BeaconDataExtract" ascii fullword
        $c6 = "__imp__BeaconPrintf" ascii fullword
        $c7 = "__imp__BeaconDataParse" ascii fullword
        $c8 = "__imp__BeaconDataExtract" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_92f05172 {
    meta:
        author = "Elastic Security"
        id = "92f05172-f15c-4077-a958-b8490378bf08"
        fingerprint = "09b1f7087d45fb4247a33ae3112910bf5426ed750e1e8fe7ba24a9047b76cc82"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC cmstp module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
        $b1 = "elevate_cmstp" ascii fullword
        $b2 = "$pdata$elevate_cmstp" ascii fullword
        $b3 = "$unwind$elevate_cmstp" ascii fullword
        $c1 = "_elevate_cmstp" ascii fullword
        $c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
        $c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
        $c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
        $c5 = "OLDNAMES"
        $c6 = "__imp__BeaconDataParse" ascii fullword
        $c7 = "_willAutoElevate" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5 {
    meta:
        author = "Elastic Security"
        id = "417239b5-cf2d-4c85-a022-7a8459c26793"
        fingerprint = "292afee829e838f9623547f94d0561e8a9115ce7f4c40ae96c6493f3cc5ffa9b"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies UAC token module from Cobalt Strike"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
        $b1 = "$pdata$is_admin_already" ascii fullword
        $b2 = "$unwind$is_admin" ascii fullword
        $b3 = "$pdata$is_admin" ascii fullword
        $b4 = "$unwind$is_admin_already" ascii fullword
        $b5 = "$pdata$RunAsAdmin" ascii fullword
        $b6 = "$unwind$RunAsAdmin" ascii fullword
        $b7 = "is_admin_already" ascii fullword
        $b8 = "is_admin" ascii fullword
        $b9 = "process_walk" ascii fullword
        $b10 = "get_current_sess" ascii fullword
        $b11 = "elevate_try" ascii fullword
        $b12 = "RunAsAdmin" ascii fullword
        $b13 = "is_ctfmon" ascii fullword
        $c1 = "_is_admin_already" ascii fullword
        $c2 = "_is_admin" ascii fullword
        $c3 = "_process_walk" ascii fullword
        $c4 = "_get_current_sess" ascii fullword
        $c5 = "_elevate_try" ascii fullword
        $c6 = "_RunAsAdmin" ascii fullword
        $c7 = "_is_ctfmon" ascii fullword
        $c8 = "_reg_query_dword" ascii fullword
        $c9 = ".drectve" ascii fullword
        $c10 = "_is_candidate" ascii fullword
        $c11 = "_SpawnAsAdmin" ascii fullword
        $c12 = "_SpawnAsAdminX64" ascii fullword
    condition:
        1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
    meta:
        author = "Elastic Security"
        id = "29374056-03ce-484b-8b2d-fbf75be86e27"
        fingerprint = "4cd7552a499687ac0279fb2e25722f979fc5a22afd1ea4abba14a2ef2002dd0f"
        creation_date = "2021-03-23"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike MZ Reflective Loader."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3 {
    meta:
        author = "Elastic Security"
        id = "949f10e3-68c9-4600-a620-ed3119e09257"
        fingerprint = "34e04901126a91c866ebf61a61ccbc3ce0477d9614479c42d8ce97a98f2ce2a7"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 {
    meta:
        author = "Elastic Security"
        id = "8751cdf9-4038-42ba-a6eb-f8ac579a4fbb"
        fingerprint = "0988386ef4ba54dd90b0cf6d6a600b38db434e00e569d69d081919cdd3ea4d3f"
        creation_date = "2021-03-25"
        last_modified = "2021-08-23"
        description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_8519072e {
    meta:
        author = "Elastic Security"
        id = "8519072e-3e43-470b-a3cf-18f92b3f31a2"
        fingerprint = "9fc88b798083adbcf25f9f0b35fbb5035a98cdfe55377de96fa0353821de1cc8"
        creation_date = "2021-03-25"
        last_modified = "2021-10-04"
        description = "Identifies Cobalt Strike trial/default versions"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "User-Agent:"
        $a2 = "wini"
        $a3 = "5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii fullword
        $a4 = /[^0-9";.\/]([0-9]{1,3}\.){3}[0-9]{1,3}[^0-9";.\/]/
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d {
    meta:
        author = "Elastic Security"
        id = "663fc95d-2472-4d52-ad75-c5d86cfc885f"
        fingerprint = "d0f781d7e485a7ecfbbfd068601e72430d57ef80fc92a993033deb1ddcee5c48"
        creation_date = "2021-04-01"
        last_modified = "2021-12-17"
        description = "Identifies CobaltStrike via unidentified function code"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        author = "Elastic Security"
        id = "b54b94ac-6ef8-4ee9-a8a6-f7324c1974ca"
        fingerprint = "2344dd7820656f18cfb774a89d89f5ab65d46cc7761c1f16b7e768df66aa41c8"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep obfuscation routine"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc {
    meta:
        author = "Elastic Security"
        id = "f0b627fc-97cd-42cb-9eae-1efb0672762d"
        fingerprint = "fbc94bedd50b5b943553dd438a183a1e763c098a385ac3a4fc9ff24ee30f91e1"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon reflective loader"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c {
    meta:
        author = "Elastic Security"
        id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
        fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for beacon sleep PDB"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
        $a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
        $a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616 {
    meta:
        author = "Elastic Security"
        id = "a3fb2616-b03d-4399-9342-0fc684fb472e"
        fingerprint = "c15cf6aa7719dac6ed21c10117f28eb4ec56335f80a811b11ab2901ad36f8cf0"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for browser pivot "
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "browserpivot.dll" ascii fullword
        $a2 = "browserpivot.x64.dll" ascii fullword
        $b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
        $b2 = "COBALTSTRIKE" ascii fullword
    condition:
        1 of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_CobaltStrike_8ee55ee5 {
    meta:
        author = "Elastic Security"
        id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
        fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
        creation_date = "2021-10-21"
        last_modified = "2022-01-13"
        description = "Rule for wmi exec module"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
        $a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_8d5963a2 {
    meta:
        author = "Elastic Security"
        id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
        fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
        creation_date = "2022-08-10"
        last_modified = "2022-09-29"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5 {
    meta:
        author = "Elastic Security"
        id = "1787eef5-ff00-4e19-bd22-c5dfc9488c7b"
        fingerprint = "292f15bdc978fc29670126f1bdc72ade1e7faaf1948653f70b6789a82dbee67f"
        creation_date = "2022-08-29"
        last_modified = "2022-09-29"
        description = "CS shellcode variants"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
    condition:
        1 of ($a*)
}
rule Win32_Trojan_Emotet : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        malware             = "EMOTET"
        description         = "Yara rule that detects Emotet trojan."

        tc_detection_type   = "Trojan"
        tc_detection_name   = "Emotet"
        tc_detection_factor = 5

    strings:

        $decrypt_resource_v1 = {
            55 8B EC 83 EC ?? 53 8B D9 8B C2 56 57 89 45 ?? 8B 3B 33 F8 8B C7 89 7D ?? 83 E0 ?? 
            75 ?? 8D 77 ?? EB ?? 8B F7 2B F0 83 C6 ?? 8D 0C 36 E8 ?? ?? ?? ?? 8B D0 89 55 ?? 85 
            D2 74 ?? 83 65 ?? ?? 8D 43 ?? 83 65 ?? ?? C1 EE ?? 8D 0C B0 8B F2 8B D9 2B D8 83 C3 
            ?? C1 EB ?? 3B C1 0F 47 5D ?? 85 DB 74 ?? 8B 55 ?? 8B F8 8B 0F 8D 7F ?? 33 CA 0F B6 
            C1 66 89 06 8B C1 C1 E8 ?? 8D 76 ?? 0F B6 C0 66 89 46 ?? C1 E9 ?? 0F B6 C1 66 89 46 
            ?? C1 E9 ?? 0F B6 C1 66 89 46 ?? 8B 45 ?? 40 89 45 ?? 3B C3 72 ?? 8B 7D ?? 8B 55 ?? 
            33 C0 66 89 04 7A 5F 5E 8B C2 5B 8B E5 5D C3 
        }

        $generate_filename_v1 = {
            56 57 33 C0 BF ?? ?? ?? ?? 57 50 50 6A ?? 50 FF 15 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 8B F0 56 68 ?? ?? ?? ?? 57 FF 15 ?? ?? ?? 
            ?? 83 C4 ?? 8B CE 5F 5E E9
        }

        $decrypt_resource_v2 = {
            55 8B EC 83 EC ?? 8B 41 ?? 8B 11 33 C2 53 56 8D 71 ?? 89 55 ?? 8D 58 ?? 89 45 ?? 83 
            C6 ?? F6 C3 ?? 74 ?? 83 E3 ?? 83 C3 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            8B C8 E8 ?? ?? ?? ?? FF D0 8D 14 1B B9 ?? ?? ?? ?? 52 6A ?? 50 E8 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? FF D0 89 45 ?? 85 C0 74 ?? C1 EB ?? 8B C8 57 33 C0 8D 
            14 9E 33 DB 8B FA 2B FE 83 C7 ?? C1 EF ?? 3B F2 0F 47 F8 85 FF 74 ?? 8B 16 8D 49 ?? 
            33 55 ?? 8D 76 ?? 0F B6 C2 43 66 89 41 ?? 8B C2 C1 E8 ?? 0F B6 C0 66 89 41 ?? C1 EA 
            ?? 0F B6 C2 66 89 41 ?? C1 EA ?? 0F B6 C2 66 89 41 ?? 3B DF 72 ?? 8B 45 ?? 33 D2 8B 
            4D ?? 5F 66 89 14 41 8B C1 5E 5B 8B E5 5D C3 
        }

        $generate_filename_v2 = {
            55 8B EC 81 EC ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 6A ?? 6A ?? 51 6A ?? B9 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? FF D0 85 C0 0F 88 ?? ?? ?? ?? 56 
            B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? 8B F0 8D 85 ?? ?? ?? ?? 8D [1-5] 51 
            51 50 56 8D [1-5] 68 ?? ?? ?? ?? 51 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B 
            C8 E8 ?? ?? ?? ?? FF D0 83 C4 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 
            E8 ?? ?? ?? ?? FF D0 56 6A ?? 50 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 
            E8 ?? ?? ?? ?? FF D0 B8 ?? ?? ?? ?? 5E 8B E5 5D C3 33 C0 8B E5 5D C3 
        }

        $decrypt_resource_v3 = {
            56 8B F1 BA [6-9] B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF D0 56 6A ?? 50 68 ?? ?? ?? ?? 
            BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 59 FF D0 5E C3 
        }

        $generate_filename_v3 = {
            55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8B F1 8B FA 6A ?? 8D 4D ?? E8 ?? ?? ?? ?? BB ?? 
            ?? ?? ?? 8D 8D ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 53 8D 8D ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 
            C4 ?? 8D 85 ?? ?? ?? ?? BB ?? ?? ?? ?? 8B D3 56 50 BE ?? ?? ?? ?? [2-5] 8B CE E8 ?? 
            ?? ?? ?? 59 FF D0 57 8D 85 ?? ?? ?? ?? 8B D3 50 [2-5] 8B CE E8 ?? ?? ?? ?? 59 FF D0 
            8D 85 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 89 45 ?? BA ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? B9 
            ?? ?? ?? ?? 89 45 ?? B8 ?? ?? ?? ?? 66 89 45 ?? 8D 45 ?? 50 68 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? 59 FF D0 F7 D8 5F 1B C0 5E 40 5B 8B E5 5D C3 
        }

        $decrypt_resource_v4 = {
            56 57 8B FA E8 ?? ?? ?? ?? 8B F0 A1 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? ?? ?? E8 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 56 FF D0 8B 0D ?? ?? ?? ?? 
            89 44 B9 ?? A1 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 
            8B C8 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? FF D0 8B F8 A1 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? 
            ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 56 6A ?? 57 
            FF D0 5F 5E C3 
        }

        $generate_filename_snippet_v4 = {
            A1 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? 
            ?? ?? ?? A3 ?? ?? ?? ?? 56 53 FF D0 A1 ?? ?? ?? ?? 85 C0 75 ?? B9 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 56 FF D0 5F 5E 33 C9 8D 
            04 43 66 89 08 5D 5B 59 C3 
        }

        $decrypt_resource_snippet_v5 = {
            C1 EE ?? 33 C0 55 33 ED 8B D3 8D 0C B7 8B F1 2B F7 83 C6 ?? C1 EE ?? 3B F9 0F 47 F0
            85 F6 74 ?? 8B 5C 24 ?? 8B 0F 8D 7F ?? 33 CB 0F B6 C1 66 89 02 8B C1 C1 E8 ?? 8D 52
            ?? 0F B6 C0 66 89 42 ?? C1 E9 ?? 0F B6 C1 C1 E9 ?? 45 66 89 42 ?? 0F B6 C1 66 89 42
            ?? 3B EE 72 ?? 8B 5C 24 ?? 8B 44 24 ?? 33 C9 5D 66 89 0C 43 5F 5E 8B C3 5B 83 C4 ??
            C3
        }

        $decrypt_resource_snippet_v6 = {
            C1 EE ?? 33 C0 55 33 ED 8B D3 8D 0C B7 8B F1 2B F7 83 C6 ?? C1 EE ?? 3B F9 0F 47 F0
            85 F6 74 ?? 8B 5C 24 ?? 8B 0F 8D 7F ?? 33 CB 88 0A 8B C1 C1 E8 ?? 8D 52 ?? C1 E9 ??
            88 42 ?? 88 4A ?? C1 E9 ?? 45 88 4A ?? 3B EE 72 ?? 8B 5C 24 ?? 8B 44 24 ?? 5D C6 04
            03 ?? 5F 5E 8B C3 5B 83 C4 ?? C3
        }

        $liblzf_decompression_1 = {
            83 EC ?? 8B 44 24 ?? 53 55 8D 2C 11 89 4C 24 ?? 8B 54 24 ?? 33 DB 03 C2 89 6C 24 ??
            56 89 44 24 ?? 0F B6 41 ?? 8D 72 ?? 0F B6 11 C1 E2 ?? 0B D0 8D 45 ?? 89 44 24 ?? 57
            8B F9 3B C8 0F 83 ?? ?? ?? ?? 0F B6 47 ?? C1 E2 ?? 0B D0 6B C2 ?? 8B CA C1 E9 ?? 33
            CA 89 54 24 ?? 8B 54 24 ?? C1 E9 ?? 2B C8 8B 44 24 ?? 81 E1 ?? ?? ?? ?? 8B 2C 88 8B
            C7 2B 44 24 ?? 03 6C 24 ?? 89 04 8A 8B C7 8B 54 24 ?? 2B C5 48 89 44 24 ?? 3D ?? ??
            ?? ?? 0F 8D ?? ?? ?? ?? 3B EA 0F 86 ?? ?? ?? ?? 8A 45 ?? 3A 47 ?? 0F 85 ?? ?? ?? ??
            0F B6 55 ?? 8D 4F ?? 0F B6 45 ?? 89 4C 24 ?? 0F B6 09 C1 E2 ?? 0B D0 C1 E1 ?? 0F B6
            07 0B C8 3B D1 0F 85 ?? ?? ?? ?? 8B 44 24 ?? B9 ?? ?? ?? ?? 2B C7 3B C1 6A ?? 0F 47
            C1 89 44 24 ?? 8D 46 ?? 5A 3B 44 24 ?? 72 ?? 33 C9 8B C6 85 DB 0F 94 C1 2B C1 83 C0
            ?? 3B 44 24 ?? 0F 83 ?? ?? ?? ?? 8B C6 8D 4B ?? 2B C3 88 48 ?? 33 C0 85 DB 8B 5C 24
            ?? 0F 94 C0 2B F0 83 FB ?? 0F 86 ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 0F 85 ?? ??
            ?? ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 0F 85 ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 0F 85
            ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 0F 85 ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A 47
        }

        $liblzf_decompression_2 = {
            0F 85 ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 0F 85 ?? ?? ?? ?? 8A 45 ?? 6A ?? 5A 3A
            47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45
            ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47
            ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ??
            6A ?? 5A 3A 47 ?? 75 ?? 8A 45 ?? 6A ?? 5A 3A 47 ?? 75 ?? 8D 0C 3A 2B EF 42 41 3B D3
            73 ?? 8A 04 29 3A 01 74 ?? 8B 5C 24 ?? 83 EA ?? 83 FA ?? 73 ?? 8B CB 8A C2 C1 F9 ??
            C0 E0 ?? 02 C8 88 0E 46 EB ?? 8B C3 C1 F8 ?? 2C ?? 88 06 8D 42 ?? 88 46 ?? 83 C6 ??
            8B 7C 24 ?? 8B 44 24 ?? 47 88 1E 03 FA 33 DB 83 C6 ?? 3B F8 72 ?? 8B 6C 24 ?? 8D 46
            ?? 3B 44 24 ?? 76 ?? 33 C0 EB ?? 3B 74 24 ?? 73 ?? 8A 07 43 88 06 46 8B 44 24 ?? 47
            83 FB ?? 75 ?? C6 46 ?? ?? 33 DB 46 3B F8 73 ?? 8B 54 24 ?? E9 ?? ?? ?? ?? 8A 07 43
            88 06 46 47 83 FB ?? 75 ?? C6 46 ?? ?? 33 DB 46 3B FD 72 ?? 8B CE 8D 53 ?? 2B CB 88
            51 ?? 33 C9 85 DB 0F 94 C1 2B F1 2B 74 24 ?? 8B C6 5F 5E 5D 5B 83 C4 ?? C3
        }

        $decrypt_resource_snippet_v7 = {
            C1 EE ?? 3B F9 0F 47 F0 85 F6 74 ?? 8B 5C 24 ?? 8B 0F 8D 7F ?? 33 CB 0F B6 C1 66 89
            02 8B C1 C1 E8 ?? 8D 52 ?? 0F B6 C0 66 89 42 ?? C1 E9 ?? 0F B6 C1 C1 E9 ?? 45 66 89
            42 ?? 0F B6 C1 66 89 42 ?? 3B EE 72 ?? 8B 5C 24 ?? 8B 44 24 ?? 33 C9 5D 66 89 0C 43
            5F 5E 8B C3 5B 83 C4 ?? C3 
        }

        $state_machine_snippet_v7 = {
            8D 84 24 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B 
            94 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8D 84 24 
            ?? ?? ?? ?? 50 68 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B 54 24 ?? 
            8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8D 94 
            24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? FF 74 24 
            ?? 8B F0 FF B4 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? F7 DE 8B 94 24 ?? ?? ?? ?? 1B F6 
            81 E6 ?? ?? ?? ?? 81 C6 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF B4 24 ?? ?? ?? ?? FF B4 24 ?? 
            ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8B 4C 24 ?? E8 ?? ?? ?? ?? 83 C4 ?? E9 
        }

    condition:
        uint16(0) == 0x5A4D and 
        (
            $decrypt_resource_v1 and 
            $generate_filename_v1
        ) or 
        (
            $decrypt_resource_v2 and 
            $generate_filename_v2
        ) or
        (
            $decrypt_resource_v3 and 
            $generate_filename_v3
        ) or
        (
            $decrypt_resource_v4 and 
            $generate_filename_snippet_v4
        ) or
        (
            $decrypt_resource_snippet_v5 and
            all of ($liblzf_decompression_*)
        ) or
        (
            $decrypt_resource_snippet_v6 and
            all of ($liblzf_decompression_*)
        ) or
        (
            $decrypt_resource_snippet_v7 and
            $state_machine_snippet_v7
        )
}
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule MALW_trickbot_bankBot : Trojan
{
meta:
 author = "Marc Salinas @Bondey_m"
 description = "Detects Trickbot Banking Trojan"
strings:
$str_trick_01 = "moduleconfig"
$str_trick_02 = "Start"
$str_trick_03 = "Control"
$str_trick_04 = "FreeBuffer"
$str_trick_05 = "Release"
condition:
all of ($str_trick_*)
}
rule MALW_systeminfo_trickbot_module :
Trojan
{
meta:
author = "Marc Salinas @Bondey_m"
description = "Detects systeminfo module from Trickbot Trojan"
strings:
$str_systeminf_01 = "<program>"
$str_systeminf_02 = "<service>"
$str_systeminf_03 = "</systeminfo>"
$str_systeminf_04 =
"GetSystemInfo.pdb"
$str_systeminf_05 = "</autostart>"
$str_systeminf_06 = "</moduleconfig>"
condition:
all of ($str_systeminf_*)
}
rule MALW_dllinject_trickbot_module : Trojan
{
meta:
author = "Marc Salinas @Bondey_m"
description = " Detects dllinject module from Trickbot Trojan"
strings:
$str_dllinj_01 = "user_pref("
$str_dllinj_02 = "<ignore_mask>"
$str_dllinj_03 = "<require_header>"
$str_dllinj_04 = "</dinj>"
condition:
all of ($str_dllinj_*)
}
rule MALW_mailsercher_trickbot_module :
Trojan
{
meta:
author = "Marc Salinas @Bondey_m"
description = " Detects mailsearcher module from Trickbot Trojan"
strings:
$str_mails_01 = "mailsearcher"
$str_mails_02 = "handler"
$str_mails_03 = "conf"
$str_mails_04 = "ctl"
$str_mails_05 = "SetConf"
$str_mails_06 = "file"
$str_mails_07 = "needinfo"
$str_mails_08 = "mailconf"
condition:
all of ($str_mails_*)
}



/*
YARA Rule Set
Author: The DFIR Report
Date: 2022-08-08
Identifier: BumbleBee Case 13387
Reference: https://thedfirreport.com
*/


/* Rule Set ----------------------------------------------------------------- */


rule bumblebee_13387_VulnRecon_dll {
   meta:
      description = "BumbleBee - file VulnRecon.dll"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2022-08-08"
      hash1 = "a9e90587c54e68761be468181e56a5ba88bac10968ff7d8c0a1c01537158fbe8"
   strings:
      $x1 = "Use VulnRecon.exe  -i, --SystemInfo  to execute this command" fullword wide
      $x2 = "Use VulnRecon.exe  -v, --Vulnerability  to execute this command" fullword wide
      $x3 = "Use VulnRecon.exe  -h, --HotFixes  to execute this command" fullword wide
      $x4 = "Use VulnRecon.exe -m, --MicrosoftUpdates to execute this command" fullword wide
      $x5 = "Use VulnRecon.exe   -s, --SupportedCve  to execute this command" fullword wide
      $s6 = "VulnRecon.dll" fullword wide
      $s7 = "VulnRecon.Commands.SystemCommands" fullword ascii
      $s8 = "VulnRecon.Commands.CveCommands" fullword ascii
      $s9 = "VulnRecon.Commands" fullword ascii
      $s10 = "VulnRecon.CommandLine" fullword ascii
      $s11 = "D:\\work\\rt\\VulnRecon\\VulnRecon\\obj\\Release\\net5.0\\VulnRecon.pdb" fullword ascii
      $s12 = "VulnRecon.Commands.ToolsCommand" fullword ascii
      $s13 = "Using VulnRecon.exe -o or VulnRecon.exe --OptionName" fullword wide
      $s14 = "commandVersion" fullword ascii
      $s15 = "GetSystemInfoCommand" fullword ascii
      $s16 = "CreateGetSupportedCveCommand" fullword ascii
      $s17 = "CreateWindowsVersionCommand" fullword ascii
      $s18 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s19 = "get_CommandVersion" fullword ascii
      $s20 = "<CommandVersion>k__BackingField" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and
      1 of ($x*) and 4 of them
}


rule bumblebee_13387_VulnRecon_exe {
   meta:
      description = "BumbleBee - file VulnRecon.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2022-08-08"
      hash1 = "eb4cba90938df28f6d8524be639ed7bd572217f550ef753b2f2d39271faddaef"
   strings:
      $s1 = "hostfxr.dll" fullword wide
      $s2 = "--- Invoked %s [version: %s, commit hash: %s] main = {" fullword wide
      $s3 = "This executable is not bound to a managed DLL to execute. The binding value is: '%s'" fullword wide
      $s4 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\win-x64.Release\\corehost\\cli\\apphost\\standalone\\Release\\apphost.pdb" fullword ascii
      $s5 = "VulnRecon.dll" fullword wide
      $s6 = "api-ms-win-crt-runtime-l1-1-0.dll" fullword ascii
      $s7 = "  - %s&apphost_version=%s" fullword wide
      $s8 = "api-ms-win-crt-convert-l1-1-0.dll" fullword ascii
      $s9 = "api-ms-win-crt-math-l1-1-0.dll" fullword ascii
      $s10 = "api-ms-win-crt-time-l1-1-0.dll" fullword ascii
      $s11 = "api-ms-win-crt-stdio-l1-1-0.dll" fullword ascii
      $s12 = "api-ms-win-crt-heap-l1-1-0.dll" fullword ascii
      $s13 = "api-ms-win-crt-string-l1-1-0.dll" fullword ascii
      $s14 = "The managed DLL bound to this executable is: '%s'" fullword wide
      $s15 = "A fatal error was encountered. This executable was not bound to load a managed DLL." fullword wide
      $s16 = "api-ms-win-crt-locale-l1-1-0.dll" fullword ascii
      $s17 = "Showing error dialog for application: '%s' - error code: 0x%x - url: '%s'" fullword wide
      $s18 = "Failed to resolve full path of the current executable [%s]" fullword wide
      $s19 = "https://go.microsoft.com/fwlink/?linkid=798306" fullword wide
      $s20 = "The managed DLL bound to this executable could not be retrieved from the executable image." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      all of them
}


rule bumblebee_13387_wab {
   meta:
      description = "BumbleBee - file wab.exe"
      author = "TheDFIRReport"
      reference = "https://thedfirreport.com"
      date = "2022-08-08"
      hash1 = "1cf28902be615c721596a249ca85f479984ad85dc4b19a7ba96147e307e06381"
   strings:
      $s1 = "possibility terminate nation inch ducked ski accidentally usage absent reader rowing looking smack happily strings disadvantage " ascii
      $s2 = "pfxvex450gd81.exe" fullword ascii
      $s3 = "31403272414143" ascii /* hex encoded string '1@2rAAC' */
      $s4 = "s wolf save detail surgery short vigour uttered fake proposal moustache accustomed lock been vegetable maximum ownership specifi" ascii
      $s5 = "130 Dial password %d propose7177! Syllable( warrior stretching Angry 83) sabotage %s" fullword wide
      $s6 = "possibility terminate nation inch ducked ski accidentally usage absent reader rowing looking smack happily strings disadvantage " ascii
      $s7 = "accomplish course Content 506) arched organ Travels" fullword ascii
      $s8 = "123 serve edit. 693 Poison@ mercy " fullword wide
      $s9 = "Top wealthy! fish 760? pier%complaint July nicer! 587) %s shark+ " fullword wide
      $s10 = " Approximate- Choked- %s %s, " fullword wide
      $s11 = "niece beacon dwelling- Headlong Intellectual+" fullword ascii
      $s12 = ">Certainty holes) cherries Proceeding Active+ surname Rex/ gets" fullword wide
      $s13 = "+Enthusiastic@ Couple? %s, shy %d %d) plume " fullword wide
      $s14 = " again workroom front leader height mantle mother sudden illness discontent who finest southern nature supplement normally hopef" ascii
      $s15 = "Advantage %s+ Creation. officially/ Affirmative %s? %s " fullword ascii
      $s16 = "Mind@ falcon+ illumination repair/ %s! " fullword ascii
      $s17 = "%Truthful- %d/ 161! Checking 786/ Mob " fullword wide
      $s18 = "#%s. %s Door observed- lazy? Quiet@ " fullword wide
      $s19 = "wrong comer? %s) Designer$ 372" fullword wide
      $s20 = "Fleet( %d, lads. %d! %d %s 445" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
      }
      rule Windows_Trojan_Qbot_92c67a6d {
    meta:
        author = "Elastic Security"
        id = "92c67a6d-9290-4cd9-8123-7dace2cf333d"
        fingerprint = "4719993107243a22552b65e6ec8dc850842124b0b9919a6ecaeb26377a1a5ebd"
        creation_date = "2021-02-16"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "636e2904276fe33e10cce5a562ded451665b82b24c852cbdb9882f7a54443e02"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 33 C0 59 85 F6 74 2D 83 66 0C 00 40 89 06 6A 20 89 46 04 C7 46 08 08 00 }
    condition:
        all of them
}

rule Windows_Trojan_Qbot_d91c1384 {
    meta:
        author = "Elastic Security"
        id = "d91c1384-839f-4062-8a8d-5cda931029ae"
        fingerprint = "1b47ede902b6abfd356236e91ed3e741cf1744c68b6bb566f0d346ea07fee49a"
        creation_date = "2021-07-08"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }
    condition:
        all of them
}

rule Windows_Trojan_Qbot_7d5dc64a {
    meta:
        author = "Elastic Security"
        id = "7d5dc64a-a597-44ac-a0fd-cefffc5e9cff"
        fingerprint = "ab80d96a454e0aad56621e70be4d55f099c41b538a380feb09192d252b4db5aa"
        creation_date = "2021-10-04"
        last_modified = "2022-01-13"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "a2bacde7210d88675564106406d9c2f3b738e2b1993737cb8bf621b78a9ebf56"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "%u.%u.%u.%u.%u.%u.%04x" ascii fullword
        $a2 = "stager_1.dll" ascii fullword
    condition:
        all of them
}

rule Windows_Trojan_Qbot_6fd34691 {
    meta:
        author = "Elastic Security"
        id = "6fd34691-10e4-4a66-85ff-1b67ed3da4dd"
        fingerprint = "187fc04abcba81a2cbbe839adf99b8ab823cbf65993c8780d25e7874ac185695"
        creation_date = "2022-03-07"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 75 C9 8B 45 1C 89 45 A4 8B 45 18 89 45 A8 8B 45 14 89 45 AC 8B }
        $a2 = "\\stager_1.obf\\Benign\\mfc\\" wide
    condition:
        any of them
}

rule Windows_Trojan_Qbot_3074a8d4 {
    meta:
        author = "Elastic Security"
        id = "3074a8d4-d93c-4987-9031-9ecd3881730d"
        fingerprint = "c233a0c24576450ce286d96126379b6b28d537619e853d860e2812f521b810ac"
        creation_date = "2022-06-07"
        last_modified = "2022-07-18"
        threat_name = "Windows.Trojan.Qbot"
        reference_sample = "c2ba065654f13612ae63bca7f972ea91c6fe97291caeaaa3a28a180fb1912b3a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "qbot" wide
        $a2 = "stager_1.obf\\Benign\\mfc" wide
        $a3 = "common.obf\\Benign\\mfc" wide
        $a4 = "%u;%u;%u;"
        $a5 = "%u.%u.%u.%u.%u.%u.%04x"
        $a6 = "%u&%s&%u"
        $get_string1 = { 33 D2 8B ?? 6A 5A 5? F7 ?? 8B ?? 08 8A 04 ?? 8B 55 ?? 8B ?? 10 3A 04 ?? }
        $get_string2 = { 33 D2 8B ?? F7 75 F4 8B 45 08 8A 04 02 32 04 ?? 88 04 ?? ?? 83 ?? 01 }
        $set_key = { 8D 87 00 04 00 00 50 56 E8 ?? ?? ?? ?? 59 8B D0 8B CE E8 }
        $do_computer_use_russian_like_keyboard = { B9 FF 03 00 00 66 23 C1 33 C9 0F B7 F8 66 3B 7C 4D }
        $execute_each_tasks = { 8B 44 0E ?? 85 C0 74 ?? FF D0 EB ?? 6A 00 6A 00 6A 00 FF 74 0E ?? E8 ?? ?? ?? ?? 83 C4 10 }
        $generate_random_alpha_num_string = { 57 E8 ?? ?? ?? ?? 48 50 8D 85 ?? ?? ?? ?? 6A 00 50 E8 ?? ?? ?? ?? 8B 4D ?? 83 C4 10 8A 04 38 88 04 0E 46 83 FE 0C }
        $load_base64_dll_from_file_and_inject_into_targets = { 10 C7 45 F0 50 00 00 00 83 65 E8 00 83 7D F0 0B 73 08 8B 45 F0 89 }
    condition:
        6 of them
}
////////////////////////////////////////////////////////
//////////////////// ZLOADER Loader ////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////

import "pe"
rule crime_win32_zloader_load_1 {

meta:
    description = "Detects Zloader loader 1.1.20"
    author = "@VK_Intel"
    reference = "https://twitter.com/malwrhunterteam/status/1240664014121828352"
    date = "2020-03-21"


strings:
    $str1 = "antiemule-loader-bot32.dll"

    $loop = {EE 03 00 00 E9 03 00 00 EE 03 00 00 EF 03 00 00 F0 03 00 00 EE 03 00 00 EE 03 00 00 EA 03 00 00 EC 03 00 00 EB 03 00 00 ED 03 00 00}
    $decoder_op = {55 89 e5 53 57 56 8b ?? ?? 85 f6 74 ?? 8b ?? ?? 6a 00 53 e8 ?? ?? ?? ?? 83 c4 08 a8 01 75 ?? 8b ?? ?? ?? ?? ?? 89 f9 e8 ?? ?? ?? ?? 89 c1 0f ?? ?? 66 ?? ?? 66 ?? ?? 74 ?? bb 01 00 00 00 eb ?? 89 d8 99 f7 f9 0f ?? ?? ?? 8b ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? 8d ?? ?? 74 ?? 8d ?? ?? 66 83 fa 5f 72 ?? 66 83 f8 0d 77 ?? ba 00 26 00 00 0f a3 c2 72 ?? eb ?? 31 f6 eb ?? 89 de eb ?? 8b ?? ?? 89 f0 5e 5f 5b 5d c3}


condition:
( uint16(0) == 0x5a4d and pe.exports("DllRegisterServer") and
( 2 of them )
) or ( all of them )
}

import "pe"

////////////////////////////////////////////////////////
//////////////////// ZLOADER hVNC ////////////////////
////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
import "pe"
rule crime_win32_hvnc_zloader1_hvnc_generic
{
meta:

    description = "Detects Zloader hidden VNC"
    author = "@VK_Intel"
    reference = "https://twitter.com/malwrhunterteam/status/1240664014121828352"
    date = "2020-03-21"

    condition:
        pe.exports("VncStartServer") and pe.exports("VncStopServer")
}
import "pe"


rule crime_trickbot_bazar_loader {

 meta:

  author = "AT&T Alien Labs"

  description = "TrickBot BazarLoader"

  copyright = "Alienvault Inc. 2020"

  reference = "https://otx.alienvault.com/pulse/5ea7262636e7f750733c7436"

   

 strings:

   $code1 = {

             49 8B CD 4C 8D [4] 00 7E 23 4C 8D 44 3B FF 66 66 66

             90 66 66 66 90 41 0F B6 00 48 83 C1 01 49 83 E8 01

             48 3B CB 42 88 44 21 0B 7C EA 8D 43 01 46 88 6C 23

             0C 4C 63 C8 49 83 F9 3E 7D 15 41 B8 3E 00 00 00 4B

             8D 4C 21 0C B2 01 4D 2B C1 E8 [4] 4C 8B 4C 24 48 48

             8B 4C 24 40 48 8D 44 24 50 48 89 44 24 28 41 B8 4C

             00 00 00 49 8B D4 44 89 6C 24 20 4C 89 6C 24 50 FF

             15 [4] 85 C0 4C 8B 64 24 70 75 2C

            }


   $str = { 25 73 20 28 25 73 3A 25 64 29 0A 25 73 } //"%s (%s:%d)\\n%s"

       

  condition:

   uint16(0) == 0x5A4D and filesize < 3MB

   and $code1 and $str


}


rule crime_trickbot_loaders_signed

{


 meta:

  author = "AT&T Alien Labs"

  description = "Signed TrickBot Loaders"

  copyright = "AlienVault Inc. 2020"

  reference = "https://otx.alienvault.com/pulse/5df94019452f666b340101d7"


 condition:

 uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

 filesize < 3MB and

 for any i in (0..pe.number_of_signatures - 1): (

 pe.signatures[i].serial == "0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86" or

 pe.signatures[i].serial == "09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9" or

 pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or

 pe.signatures[i].serial == "00:f8:84:e7:14:62:0f:2f:4c:f8:4c:b3:f1:5d:7b:fd:0c" or

 pe.signatures[i].serial == "71:c8:df:61:e6:db:0a:35:fa:ff:ef:14:f1:86:5e" or

 pe.signatures[i].serial == "13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40" or

 pe.signatures[i].serial == "33:09:fa:db:8d:a0:ed:2e:fa:1e:1d:69:1e:36:02:2d" or

 pe.signatures[i].serial == "00:94:8a:ce:cb:66:31:be:d2:8a:15:f6:66:d6:36:9b:54" or

 pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" or

 pe.signatures[i].serial == "00:88:40:c3:f9:be:3a:91:d9:f8:4c:00:42:e9:b5:30:56" or

 pe.signatures[i].serial == "0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27" or

 pe.signatures[i].serial == "04:dc:6d:94:35:b9:50:06:59:64:3a:d8:3c:00:5e:4a" or

 pe.signatures[i].serial == "0d:dc:e8:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" or

 pe.signatures[i].serial == "1d:8a:23:3c:ed:ec:0e:13:df:1b:da:82:48:dc:79:a5" or

 pe.signatures[i].serial == "09:fc:1f:b0:5c:4b:06:f4:06:df:76:39:9b:fb:75:b8" or

 pe.signatures[i].serial == "00:88:43:67:98:3f:9c:0e:38:86:2c:06:ed:92:c8:91:ad"

 )    

}




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
      8 of the

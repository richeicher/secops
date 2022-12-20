rule HiddenTear : HiddenTear {
    meta:
      description = "Hidden Tear Payload present v2"
      author = "Rich Eicher rich.eicher@rubrik.com @richeicher"    
    strings:
$a = { F5 E8 FF F5 F5 E8 FF F5 F5 E8 FF F5 F5 E8 FF F5 }
$b = { 00 00 07 E0 00 00 07 E0 00 00 07 E0 00 00 07 E0 }
$c = { E9 E9 FF E9 E9 E9 FF E9 E9 E9 FF E9 E9 E9 FF E9 }

    condition:
        any of them
}

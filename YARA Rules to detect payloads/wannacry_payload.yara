rule WannaCry : WannaCry {
    meta:
      description = "WannaCry Payload present v2"
      author = "Rich Eicher rich.eicher@rubrik.com @richeicher"    
    strings:
$a = { 11 5D 3D C3 6A 41 31 C3 10 5D 3D C3 92 41 33 C3 }
$b = { 90 90 90 90 51 8D 44 24 02 8D 4C 24 03 50 51 B9 }
$c = { C0 83 E1 03 F3 A4 BF A0 12 43 00 83 C9 FF F2 AE }

    condition:
        any of them
} 

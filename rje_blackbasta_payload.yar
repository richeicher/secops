rule WannaCry : BlackBasta {
    meta:
      description = "BlackBasta Payload present v1"
      author = "Rich Eicher"    
    strings:
$a = { AD A3 A3 B7 A3 D1 A3 E0 EA A3 A3 4F A3 03 BF A3 }
$b = { A3 43 2D A3 BB A3 A3 2C A3 E4 A3 E7 A3 F0 A3 A9 }
$c = { 2F E1 CF 2B B8 60 AE 17 03 6D 38 31 67 F3 7D 38 }

    condition:
        any of them
} 

rule QakBot : QakBot {
    meta:
      description = "QakBot Payload present v3 4/20"
      author = "Rich Eicher"    
    strings:
$a = { FF 83 C0 90 E9 97 30 FF FF 83 C0 90 E9 E7 1B FF }
$b = { EB 07 8B C6 E8 1B DC F8 FF 33 C0 5A 59 59 64 89 }
$c = { 36 00 32 00 3B 00 00 00 0A 00 00 00 26 00 23 00 }

    condition:
        any of them
} 










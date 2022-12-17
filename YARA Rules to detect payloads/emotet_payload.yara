rule Emotet : Emotet {
    meta:
      description = "Emotet Payload present v1"
      author = "Rich Eicher"    
    strings:
$a = { 4F 54 4E 44 4D 6B 42 4D 4D 6B 41 38 48 54 59 7A }
$b = { 50 68 38 30 59 4D 2B 2B 78 4C 2F 4E 76 32 64 61 }
$c = { 7A 64 4A 37 42 4C 66 45 69 67 63 70 63 43 71 4A }

    condition:
        any of them
} 










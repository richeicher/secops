rule avoslocker : avoslocker {
    meta:
      description = "avoslocker payload present v1"
      author = "Rich Eicher"    
    strings:
$a = { 55 8B EC 8B 45 08 83 E8 01 74 1E 83 E8 01 74 19 }
$b = { 66 0F 7E D0 66 0F 73 DA 04 66 0F 7E D7 66 0F 73 }
$c = { 9D 5C FC FF FF 8B 95 C0 F6 FF FF 85 D2 0F 84 48 }

    condition:
        any of them
}

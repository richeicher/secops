rule avoslocker : avoslocker {
    meta:
      description = "avoslocker payload present v1"
      author = "Rich Eicher"    
    strings:
$a = { 6A 01 50 8D 45 0C 50 FF 75 F0 E8 76 9A FF FF 09 }
$b = { E2 66 0F FE E8 66 0F DB D9 66 0F 72 D1 10 66 0F }
$c = { 01 74 2F 83 F9 0C 75 42 85 F6 75 B0 8D 45 D8 50 }

    condition:
        any of them
}

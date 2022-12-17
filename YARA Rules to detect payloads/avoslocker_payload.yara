rule avoslocker : avoslocker {
    meta:
      description = "avoslocker payload present v3"
      author = "Rich Eicher"    
    strings:
$a = { 65 00 6E 00 2D 00 61 00 75 00 00 00 65 00 6E 00 }
$b = { 74 00 61 00 2D 00 69 00 6E 00 00 00 74 00 65 00 }
$c = { 00 00 00 00 58 69 D1 3F 00 00 00 00 58 69 D1 3F }

    condition:
        any of them
}

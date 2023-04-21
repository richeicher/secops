rule zloader : zloader {
    meta:
      description = "zloader payload present v2 4/20"
      author = "Rich Eicher"    
    strings:
$a = { CD CD CD CD 66 66 66 66 66 66 66 66 66 66 66 66 }
$b = { 06 06 06 06 06 06 06 06 61 61 61 61 61 61 61 61 }
$c = { B6 42 E8 0F B6 42 EA 5E 0F 9F C1 8B 46 E9 8B EC }

    condition:
        any of them
}

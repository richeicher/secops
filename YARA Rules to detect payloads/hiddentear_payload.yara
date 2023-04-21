rule HiddenTear : HiddenTear {
    meta:
      description = "Hidden Tear Payload present v4 4/20"
      author = "Rich Eicher rich.eicher@rubrik.com @richeicher"    
    strings:
$a = { 3A F3 FF A0 A6 C5 FF D1 D1 D1 FF C8 C8 C8 FF C9 }
$b = { 23 FE FF 4A 5D DE FF 9F A3 BF FF DA DA DC FF DD }
$c = { 20 F7 FF 07 22 FE FF 13 2F FD FF 4E 63 E9 FF 85 }

    condition:
        any of them
}

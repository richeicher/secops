import "pe"


rule crime_trickbot_bazar_loader {

 meta:

  author = "AT&T Alien Labs"

  description = "TrickBot BazarLoader"

  copyright = "Alienvault Inc. 2020"

  reference = "https://otx.alienvault.com/pulse/5ea7262636e7f750733c7436"

   

 strings:

   $code1 = {

             49 8B CD 4C 8D [4] 00 7E 23 4C 8D 44 3B FF 66 66 66

             90 66 66 66 90 41 0F B6 00 48 83 C1 01 49 83 E8 01

             48 3B CB 42 88 44 21 0B 7C EA 8D 43 01 46 88 6C 23

             0C 4C 63 C8 49 83 F9 3E 7D 15 41 B8 3E 00 00 00 4B

             8D 4C 21 0C B2 01 4D 2B C1 E8 [4] 4C 8B 4C 24 48 48

             8B 4C 24 40 48 8D 44 24 50 48 89 44 24 28 41 B8 4C

             00 00 00 49 8B D4 44 89 6C 24 20 4C 89 6C 24 50 FF

             15 [4] 85 C0 4C 8B 64 24 70 75 2C

            }


   $str = { 25 73 20 28 25 73 3A 25 64 29 0A 25 73 } //"%s (%s:%d)\\n%s"

       

  condition:

   uint16(0) == 0x5A4D and filesize < 3MB

   and $code1 and $str


}


rule crime_trickbot_loaders_signed

{


 meta:

  author = "AT&T Alien Labs"

  description = "Signed TrickBot Loaders"

  copyright = "AlienVault Inc. 2020"

  reference = "https://otx.alienvault.com/pulse/5df94019452f666b340101d7"


 condition:

 uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and

 filesize < 3MB and

 for any i in (0..pe.number_of_signatures - 1): (

 pe.signatures[i].serial == "0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86" or

 pe.signatures[i].serial == "09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9" or

 pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or

 pe.signatures[i].serial == "00:f8:84:e7:14:62:0f:2f:4c:f8:4c:b3:f1:5d:7b:fd:0c" or

 pe.signatures[i].serial == "71:c8:df:61:e6:db:0a:35:fa:ff:ef:14:f1:86:5e" or

 pe.signatures[i].serial == "13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40" or

 pe.signatures[i].serial == "33:09:fa:db:8d:a0:ed:2e:fa:1e:1d:69:1e:36:02:2d" or

 pe.signatures[i].serial == "00:94:8a:ce:cb:66:31:be:d2:8a:15:f6:66:d6:36:9b:54" or

 pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" or

 pe.signatures[i].serial == "00:88:40:c3:f9:be:3a:91:d9:f8:4c:00:42:e9:b5:30:56" or

 pe.signatures[i].serial == "0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27" or

 pe.signatures[i].serial == "04:dc:6d:94:35:b9:50:06:59:64:3a:d8:3c:00:5e:4a" or

 pe.signatures[i].serial == "0d:dc:e8:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" or

 pe.signatures[i].serial == "1d:8a:23:3c:ed:ec:0e:13:df:1b:da:82:48:dc:79:a5" or

 pe.signatures[i].serial == "09:fc:1f:b0:5c:4b:06:f4:06:df:76:39:9b:fb:75:b8" or

 pe.signatures[i].serial == "00:88:43:67:98:3f:9c:0e:38:86:2c:06:ed:92:c8:91:ad"

 )    

}

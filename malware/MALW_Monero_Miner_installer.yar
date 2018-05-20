rule nkminer_monero {

 meta:

 description = "Detects installer of Monero miner that points to a NK domain"

 author = "cdoman@alienvault.com"
 
 reference = "https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner"

 tlp = "white"

 license = "MIT License"

 strings:

 $a = "82e999fb-a6e0-4094-aa1f-1a306069d1a5" nocase wide ascii

 $b = "4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRy5YeFCqgoUMnzumvS" nocase wide ascii

 $c = "barjuok.ryongnamsan.edu.kp" nocase wide ascii

 $d = "C:\\SoftwaresInstall\\soft" nocase wide ascii

 $e = "C:\\Windows\\Sys64\\intelservice.exe" nocase wide ascii

 $f = "C:\\Windows\\Sys64\\updater.exe" nocase wide ascii

 $g = "C:\\Users\\Jawhar\\documents\\" nocase wide ascii

 condition:

 any of them

}

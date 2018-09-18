rule cryptonar_ransomware {

   meta:
   
      description = "Rule to detect CryptoNar Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/"
      
   strings:
   
      $s1 = "C:\\narnar\\CryptoNar\\CryptoNarDecryptor\\obj\\Debug\\CryptoNar.pdb" fullword ascii
      $s2 = "CryptoNarDecryptor.exe" fullword wide
      $s3 = "server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has " fullword ascii
      $s4 = "Do not delete this file, else the decryption process will be broken" fullword wide
      $s5 = "key you received, and wait until the decryption process is done." fullword ascii
      $s6 = "In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]" fullword ascii
      $s7 = "Decryption process failed" fullword wide
      $s8 = "CryptoNarDecryptor.KeyValidationWindow.resources" fullword ascii
      $s9 = "Important note: Removing CryptoNar will not restore access to your encrypted files." fullword ascii
      $s10 = "johnsmith987654@tutanota.com" fullword wide
      $s11 = "Decryption process will start soon" fullword wide
      $s12 = "CryptoNarDecryptor.DecryptionProgressBarForm.resources" fullword ascii
      $s13 = "DecryptionProcessProgressBar" fullword wide
      $s14 = "CryptoNarDecryptor.Properties.Resources.resources" fullword ascii
      
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB) and all of them 
}

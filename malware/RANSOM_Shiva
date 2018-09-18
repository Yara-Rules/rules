rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransopmw"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"
    
   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide
   
   condition:

      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them 
}

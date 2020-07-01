rule jeff_dev_ransomware {

   meta:
   
      description = "Rule to detect Jeff DEV Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      
   strings:

      $s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
      $s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
      $s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
      $s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 5000KB ) and all of them
}

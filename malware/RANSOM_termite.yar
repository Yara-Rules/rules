rule termite_ransomware {

   meta:

      description = "Rule to detect Termite Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
      
   strings:
      
      $s1 = "C:\\Windows\\SysNative\\mswsock.dll" fullword ascii
      $s2 = "C:\\Windows\\SysWOW64\\mswsock.dll" fullword ascii
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
      $s5 = "C:\\Windows\\Termite.exe" fullword ascii
      $s6 = "\\Shell\\Open\\Command\\" fullword ascii
      $s7 = "t314.520@qq.com" fullword ascii
      $s8 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
      
   condition:
   
      ( uint16(0) == 0x5a4d and filesize < 6000KB ) and all of them 
}

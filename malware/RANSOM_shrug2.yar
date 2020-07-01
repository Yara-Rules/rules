rule shrug2_ransomware {

   meta:

      description = "Rule to detect Shrug2 ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
       
   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
      $s4 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
      $s5 = "C:\\Users\\" fullword wide
      $s6 = "http://clients3.google.com/generate_204" fullword wide
      $s7 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide
   
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them 
}

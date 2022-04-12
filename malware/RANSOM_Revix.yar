rule Revil_Ransomware : ransomware {
   meta:
      author = "Josh Lemon"
      description = "Detects REvil Linux - Revix 1.1 and 1.2"
      reference = "https://angle.ankura.com/post/102hcny/revix-linux-ransomware"
      date = "2021-11-04"
      version = "1.1"
      hash1 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
      hash2 = "559e9c0a2ef6898fabaf0a5fb10ac4a0f8d721edde4758351910200fe16b5fa7"
      hash3 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
   strings:
      $s1 = "Usage example: elf.exe --path /vmfs/ --threads 5" fullword ascii 
      $s2 = "uname -a && echo \" | \" && hostname" fullword ascii
      $s3 = "esxcli --formatter=csv --format-param=fields==\"WorldID,DisplayName\" vm process list" ascii
      $s4 = "awk -F \"\\\"*,\\\"*\" '{system(\"esxcli" ascii
      $s5 = "--silent (-s) use for not stoping VMs mode" fullword ascii
      $s6 = "!!!BY DEFAULT THIS SOFTWARE USES 50 THREADS!!!" fullword ascii
      $s7 = "%d:%d: Comment not allowed here" fullword ascii
      $s8 = "Error decoding user_id %d " fullword ascii 
      $s9 = "Error read urandm line %d!" fullword ascii
      $s10 = "%d:%d: Unexpected `%c` in comment opening sequence" fullword ascii
      $s11 = "%d:%d: Unexpected EOF in block comment" fullword ascii
      $s12 = "Using silent mode, if you on esxi - stop VMs manualy" fullword ascii
      $s13 = "rand: try to read %hu but get %lu bytes" fullword ascii
      $s14 = "Revix" fullword ascii
      $s15 = "without --path encrypts current dir" fullword ascii
      
      $e1 = "[%s] already encrypted" fullword ascii
      $e2 = "File [%s] was encrypted" fullword ascii
      $e3 = "File [%s] was NOT encrypted" fullword ascii
      $e4 = "Encrypting [%s]" fullword ascii

   condition:
      uint16(0) == 0x457f and filesize < 300KB and ( 4 of ($s*) and 2 of ($e*))
}

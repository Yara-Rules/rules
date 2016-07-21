rule PittyTiger {
  meta: 
    author = " (@chort0)"
    description = "Detect PittyTiger Trojan via common strings"
    strings: 
      $ptUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.; SV1)" // missing minor digit
      $ptFC001 = "FC001" fullword 
      $ptPittyTiger = "PittyTiger" fullword 
      $trjHTMLerr = "trj:HTML Err." nocase fullword 
      $trjworkFunc = "trj:workFunc start." nocase fullword 
      $trjcmdtout = "trj:cmd time out." nocase fullword 
      $trjThrtout = "trj:Thread time out." nocase fullword
      $trjCrPTdone = "trj:Create PT done." nocase fullword
      $trjCrPTerr = "trj:Create PT error: mutex already exists." nocase fullword 
      $oddPippeFailed = "Create Pippe Failed!" fullword // extra 'p'
      $oddXferingFile = "Transfering File" fullword // missing 'r' 
      $oddParasError = "put Paras Error:" fullword // abbreviated 'parameters'? 
      $oddCmdTOutkilled = "Cmd Time Out..Cmd has been killed." fullword 
condition: 
  (any of ($pt*)) and (any of ($trj*)) and (any of ($odd*)) 
  }

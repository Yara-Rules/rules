rule shimrat
{
 meta:
  description = "Detects ShimRat and the ShimRat loader"
  author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
  date = "20/11/2015"
  ref = "https://blog.fox-it.com/2016/06/15/mofang-a-politically-motivated-information-stealing-adversary/"
  
 strings:
  $dll = ".dll"
  $dat = ".dat"
  $headersig = "QWERTYUIOPLKJHG"
  $datasig = "MNBVCXZLKJHGFDS"
  $datamarker1 = "Data$$00"
  $datamarker2 = "Data$$01%c%sData"
  $cmdlineformat = "ping localhost -n 9 /c %s > nul"
  $demoproject_keyword1 = "Demo"
  $demoproject_keyword2 = "Win32App"
  $comspec = "COMSPEC"
  $shim_func1 = "ShimMain"
  $shim_func2 = "NotifyShims"
  $shim_func3 = "GetHookAPIs"


 condition:
  ($dll and $dat and $headersig and $datasig) or ($datamarker1 and $datamarker2) or ($cmdlineformat and $demoproject_keyword1 and $demoproject_keyword2 and $comspec) or ($dll and $dat and $shim_func1 and $shim_func2 and $shim_func3)
}

rule shimratreporter
{
 meta:
  description = "Detects ShimRatReporter"
  author = "Yonathan Klijnsma (yonathan.klijnsma@fox-it.com)"
  date = "20/11/2015"
  ref = "https://blog.fox-it.com/2016/06/15/mofang-a-politically-motivated-information-stealing-adversary/"


 strings:
  $IpInfo = "IP-INFO"
  $NetworkInfo = "Network-INFO"
  $OsInfo = "OS-INFO"
  $ProcessInfo = "Process-INFO"
  $BrowserInfo = "Browser-INFO"
  $QueryUserInfo = "QueryUser-INFO"
  $UsersInfo = "Users-INFO"
  $SoftwareInfo = "Software-INFO"
  $AddressFormat = "%02X-%02X-%02X-%02X-%02X-%02X"
  $proxy_str = "(from environment) = %s"

  $netuserfun = "NetUserEnum"
  $networkparams = "GetNetworkParams"

 condition:
  all of them
}

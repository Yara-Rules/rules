rule jjEncode
{
   meta:
      description = "jjencode detection"
      ref = "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
      author = "adnan.shukor@gmail.com"
      date = "10-June-2015"
      version = "1"
      impact = 3
      hide = false
   strings:
      $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword 
   condition:
      $jjencode
}

rule HelpSupportCenter
{
   meta:  
      ref = "CVE-2010-1885"
      hide = true
      impact = 5 
      author = "@d3t0n4t0r"
   strings:
      $cve20101885 = /hcp:\/\/.*?(%u?[A-F]{1,4}.*?){90}/
   condition:
       all of them
}
rule SafariWindowParentClose
{
   meta:
      ref = "Safari window.parent.close()"
      impact = 7
      author = "@d3t0n4t0r"
   strings:
      $SafariWindowParentClose_1 = /.*?.prompt\(alert\)/
      $SafariWindowParentClose_2 = /.*?.prompt\(.*?\)/
      $SafariWindowParentClose_3 = /.*?.close\(\)/
   condition:
      all of them
}
rule JavaDeploymentToolkit
{
   meta:
      ref = "CVE-2010-0887"
      impact = 7
      author = "@d3t0n4t0r"
   strings:
      $cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
      $cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
      $cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
      $cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
      $cve20100887_5 = "document.body.appendChild(" nocase fullword
      $cve20100887_6 = /.*?.launch\(.*?\)/
      $cve20100887_7 = "-J-jar -J" nocase fullword
   condition:
      3 of them
}

rule MSIETabularActivex
{
        meta:
                ref = "CVE-2010-0805"
                impact = 7
                hide = true
                author = "@d3t0n4t0r"
        strings:
                $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
                $cve20100805_2 = "DataURL" nocase fullword
                $cve20100805_3 = /value\=\"http:\/\/(.*?)\"/ nocase fullword
        condition:
                ($cve20100805_1 and $cve20100805_3) or (all of them)
}

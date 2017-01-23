/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_NGO_wuaclt
{
   
   meta:
    author = "AlienVault Labs"
  
  strings:
    $a = "%%APPDATA%%\\Microsoft\\wuauclt\\wuauclt.dat"
    $b = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"
    $c = "/news/show.asp?id%d=%d"
    
    $d = "%%APPDATA%%\\Microsoft\\wuauclt\\"
    $e = "0l23kj@nboxu"
    
    $f = "%%s.asp?id=%%d&Sid=%%d"
    $g = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SP Q%%d)"
    $h = "Cookies: UseID=KGIOODAOOK%%s"

  condition:
    ($a and $b and $c) or ($d and $e) or ($f and $g and $h)
}

rule APT_NGO_wuaclt_PDF
{
        meta:
            author = "AlienVault Labs"

    strings:
        $pdf  = "%PDF" nocase
        $comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}
    
    condition:
        $pdf at 0 and $comment in (0..200)
}

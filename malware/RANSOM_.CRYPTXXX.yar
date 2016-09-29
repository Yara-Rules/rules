/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Ransom_CryptXXX_Dropper
{
    /*
      Regla para detectar el dropper de Ransom.CryptXXX con MD5 d01fd2bb8c6296d51be297978af8b3a1
    */
    meta:
        description = "Regla para detectar RANSOM.CRYPTXXX"
        author      = "CCN-CERT"
        version     = "1.0"
        ref = "https://www.ccn-cert.cni.es/seguridad-al-dia/comunicados-ccn-cert/4002-publicado-el-informe-del-codigo-danino-ransom-cryptxxx.html"
    strings:
        $a = { 50 65 31 57 58 43 46 76 59 62 48 6F 35 }
        $b = { 43 00 3A 00 5C 00 42 00 49 00 45 00 52 00 5C 00 51 00 6D 00 6B 00 4E 00 52 00 4C 00 46 00 00 }
    condition:
        all of them
}

rule Ransom_CryptXXX_Real
{
    /*
      Regla para detectar el codigo Ransom.CryptXXX fuera del dropper con MD5 ae06248ab3c02e1c2ca9d53b9a155199
    */
    meta:
        description = "Regla para detectar Ransom.CryptXXX original"
        author      = "CCN-CERT"
        version     = "1.0"
        ref = "https://www.ccn-cert.cni.es/seguridad-al-dia/comunicados-ccn-cert/4002-publicado-el-informe-del-codigo-danino-ransom-cryptxxx.html"
    strings:
        $a = { 52 59 47 40 4A 41 59 5D 52 00 00 00 FF FF FF FF }
		$b = { 06 00 00 00 52 59 47 40 40 5A 00 00 FF FF FF FF }
		$c = { 0A 00 00 00 52 5C 4B 4D 57 4D 42 4B 5C 52 00 00 }
		$d = { FF FF FF FF 0A 00 00 00 52 5D 57 5D 5A 4B 43 70 }
		$e = { 3F 52 00 00 FF FF FF FF 06 00 00 00 52 4C 41 41 }
		$f = { 5A 52 00 00 FF FF FF FF 0A 00 00 00 52 5C 4B 4D }
		$g = { 41 58 4B 5C 57 52 00 00 FF FF FF FF 0E 00 00 00 }
		$h = { 52 2A 5C 4B 4D 57 4D 42 4B 20 4C 47 40 52 00 00 }
		$i = { FF FF FF FF 0A 00 00 00 52 5E 4B 5C 48 42 41 49 }
		$j = { 5D 52 00 00 FF FF FF FF 05 00 00 00 52 4B 48 47 }
		$k = { 52 00 00 00 FF FF FF FF 0C 00 00 00 52 4D 41 40 }
		$l = { 48 47 49 20 43 5D 47 52 00 00 00 00 FF FF FF FF }
		$m = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3F 52 00 00 }
		$n = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$o = { 3C 52 00 00 FF FF FF FF 08 00 00 00 52 49 41 41 }
		$p = { 49 42 4B 52 00 00 00 00 FF FF FF FF 06 00 00 00 }
		$q = { 52 5A 4B 43 5E 52 00 00 FF FF FF FF 08 00 00 00 }
		$v = { 52 48 3A 4C 4D 70 3F 52 00 00 00 00 FF FF FF FF }
		$w = { 0A 00 00 00 52 4F 42 42 5B 5D 4B 70 3F 52 00 00 }
		$x = { FF FF FF FF 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 }
		$y = { 3F 52 00 00 FF FF FF FF 0A 00 00 00 52 5E 5C 41 }
		$z = { 49 5C 4F 70 3C 52 00 00 FF FF FF FF 09 00 00 00 }
		$aa = { 52 4F 5E 5E 4A 4F 5A 4F 52 00 00 00 FF FF FF FF }
		$ab = { 0A 00 00 00 52 5E 5C 41 49 5C 4F 70 3D 52 00 00 }
		$ac = { FF FF FF FF 08 00 00 00 52 5E 5B 4C 42 47 4D 52 }
		
    condition:
        all of them
}

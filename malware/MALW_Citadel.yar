/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule citadel13xy
{
    
    meta:
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Citadel 1.5.x.y trojan banker"
        date = "2013-01-12" 
        version = "1.0" 
        filetype = "memory"
   
    strings:
        $a = "Coded by BRIAN KREBS for personnal use only. I love my job & wife."
        $b = "http://%02x%02x%02x%02x%02x%02x%02x%02x.com/%02x%02x%02x%02x/%02x%02x%02x%02x%02x.php"
        $c = "%BOTID%"
        $d = "%BOTNET%"
        $e = "cit_video.module"
        $f = "bc_remove"
        $g = "bc_add"
        $ggurl = "http://www.google.com/webhp"

    condition:
        3 of them
}

rule Citadel_Malware
{
    
    meta:
        author = "xylitol@temari.fr"
        date = "2015-10-08" 
        description = "Search for nss3.dll pattern indicating an hexed copy of Citadel malware to work on firefox > v23.0"
        // May only the challenge guide you
        
    strings:
        $s1 = "Coded by BRIAN KREBS for personal use only. I love my job & wife" wide ascii
        $s2 = "nss3.dll" wide ascii

        $h1 = {8B C7 EB F5 55 8B EC}
        $h2 = {55 8B EC 83 EC 0C 8A 82 00 01 00 00}
        $h3 = {3D D0 FF 1F 03 77 ?? 83 7D}
        $h4 = {83 F9 66 74 ?? 83 F9 6E 74 ?? 83 F9 76 74 ?? 83 F9 7A}

    condition:
        all of ($s*) and 2 of ($h*)
}

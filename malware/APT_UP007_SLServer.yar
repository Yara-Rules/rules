/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule dubseven_file_set
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for service files loading UP007"
    
    strings:
        $file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
        $file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
        $file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
        $file4 = "\\Microsoft\\Internet Explorer\\main.dll"
        $file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
        $file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
        $file7 = "\\Microsoft\\Internet Explorer\\mon"
        $file8 = "\\Microsoft\\Internet Explorer\\runas.exe"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        //Just a few of these as they differ
        3 of ($file*)
}

rule dubseven_dropper_registry_checks : Dropper
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for registry keys checked for by the dropper"
    
    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        all of ($reg*)
}

rule dubseven_dropper_dialog_remains : Dropper
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."
    
    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        any of them
}
        

rule maindll_mutex : Mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
        
    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}


rule SLServer_dialog_remains
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $slserver = "SLServer" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $slserver
}

rule SLServer_mutex : Mutex
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the mutex."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_command_and_control : C2
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the C2 server."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $c2 = "safetyssl.security-centers.com"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $c2
}

rule SLServer_campaign_code
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for the related campaign code."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $campaign = "wthkdoc0106"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $campaign
}

rule SLServer_unknown_string
{
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for a unique string."
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
    
    strings:
        $string = "test-b7fa835a39"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $string
}


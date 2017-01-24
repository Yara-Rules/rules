/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule WoolenGoldfish_Sample_1 
{

    meta:
        description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
        author = "Florian Roth"
        reference = "http://goo.gl/NpJpVZ"
        date = "2015/03/25"
        score = 60
        hash = "7ad0eb113bc575363a058f4bf21dbab8c8f7073a"
    
    strings:
        $s1 = "Cannot execute (%d)" fullword ascii
        $s16 = "SvcName" fullword ascii
    
    condition:
        all of them
}

rule WoolenGoldfish_Generic_1 
{

    meta:
        description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
        author = "Florian Roth"
        reference = "http://goo.gl/NpJpVZ"
        date = "2015/03/25"
        score = 90
        super_rule = 1
        hash0 = "5d334e0cb4ff58859e91f9e7f1c451ffdc7544c3"
        hash1 = "d5b2b30fe2d4759c199e3659d561a50f88a7fb2e"
        hash2 = "a42f1ad2360833baedd2d5f59354c4fc3820c475"
    
    strings:
        $x0 = "Users\\Wool3n.H4t\\"
        $x1 = "C-CPP\\CWoolger"
        $x2 = "NTSuser.exe" fullword wide
        $s1 = "107.6.181.116" fullword wide
        $s2 = "oShellLink.Hotkey = \"CTRL+SHIFT+F\"" fullword
        $s3 = "set WshShell = WScript.CreateObject(\"WScript.Shell\")" fullword
        $s4 = "oShellLink.IconLocation = \"notepad.exe, 0\"" fullword
        $s5 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" fullword
        $s6 = "wlg.dat" fullword
        $s7 = "woolger" fullword wide
        $s8 = "[Enter]" fullword
        $s9 = "[Control]" fullword
    condition:
        ( 1 of ($x*) and 2 of ($s*) ) or ( 6 of ($s*) )
}

rule WoolenGoldfish_Generic_2 
{

    meta:
        description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
        author = "Florian Roth"
        reference = "http://goo.gl/NpJpVZ"
        date = "2015/03/25"
        score = 90
        hash1 = "47b1c9caabe3ae681934a33cd6f3a1b311fd7f9f"
        hash2 = "62172eee1a4591bde2658175dd5b8652d5aead2a"
        hash3 = "7fef48e1303e40110798dfec929ad88f1ad4fbd8"
        hash4 = "c1edf6e3a271cf06030cc46cbd90074488c05564"
   
    strings:
        $s0 = "modules\\exploits\\littletools\\agent_wrapper\\release" ascii
   
    condition:
        all of them
}

rule WoolenGoldfish_Generic_3 
{

    meta:
        description = "Detects a operation Woolen-Goldfish sample - http://goo.gl/NpJpVZ"
        author = "Florian Roth"
        reference = "http://goo.gl/NpJpVZ"
        date = "2015/03/25"
        score = 90
        hash1 = "86222ef166474e53f1eb6d7e6701713834e6fee7"
        hash2 = "e8dbcde49c7f760165ebb0cb3452e4f1c24981f5"
    
    strings:
        $x1 = "... get header FATAL ERROR !!!  %d bytes read > header_size" fullword ascii
        $x2 = "index.php?c=%S&r=%x&u=1&t=%S" fullword wide
        $x3 = "connect_back_tcp_channel#do_connect:: Error resolving connect back hostname" fullword ascii
        $s0 = "kernel32.dll GetProcAddressLoadLibraryAws2_32.dll" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=%S" fullword wide
        $s2 = "Attempting to unlock uninitialized lock!" fullword ascii
        $s4 = "unable to load kernel32.dll" fullword ascii
        $s5 = "index.php?c=%S&r=%x" fullword wide
        $s6 = "%s len:%d " fullword ascii
        $s7 = "Encountered error sending syscall response to client" fullword ascii
        $s9 = "/info.dat" fullword ascii
        $s10 = "Error entering thread lock" fullword ascii
        $s11 = "Error exiting thread lock" fullword ascii
        $s12 = "connect_back_tcp_channel_init:: socket() failed" fullword ascii
   
    condition:
        ( 1 of ($x*) ) or ( 8 of ($s*) )
}

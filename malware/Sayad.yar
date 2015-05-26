/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Vinsula_Sayad_Binder : infostealer
{
    meta:
        Author      = "Vinsula, Inc"
        Date        = "2014/06/20"
        Description = "Sayad Infostealer Binder"
        Reference   = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

    strings: 
        $pdbstr = "\\Projects\\C#\\Sayad\\Source\\Binder\\obj\\Debug\\Binder.pdb" 
        $delphinativestr = "DelphiNative.dll" nocase
        $sqlite3str = "sqlite3.dll" nocase
        $winexecstr = "WinExec" 
        $sayadconfig = "base.dll" wide

    condition:
        all of them
}

rule Vinsula_Sayad_Client : infostealer
{
    meta:
        Author      = "Vinsula, Inc"
        Date        = "2014/06/20"
        Description = "Sayad Infostealer Client"
        Reference   = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"

    strings: 
        $pdbstr = "\\Projects\\C#\\Sayad\\Source\\Client\\bin\\x86\\Debug\\Client.pdb" 
        $sayadconfig = "base.dll" wide
        $sqlite3str = "sqlite3.dll" nocase
        $debugstr01 = "Config loaded" wide
        $debugstr02 = "Config parsed" wide
        $debugstr03 = "storage uploader" wide
        $debugstr04 = "updater" wide
        $debugstr05 = "keylogger" wide
        $debugstr06 = "Screenshot" wide
        $debugstr07 = "sqlite found & start collectiong data" wide
        $debugstr08 = "Machine info collected" wide
        $debugstr09 = "browser ok" wide
        $debugstr10 = "messenger ok" wide
        $debugstr11 = "vpn ok" wide
        $debugstr12 = "ftp client ok" wide
        $debugstr13 = "ftp server ok" wide
        $debugstr14 = "rdp ok" wide
        $debugstr15 = "kerio ok" wide
        $debugstr16 = "skype ok" wide
        $debugstr17 = "serialize data ok" wide
        $debugstr18 = "Keylogged" wide

    condition:
        all of them
}
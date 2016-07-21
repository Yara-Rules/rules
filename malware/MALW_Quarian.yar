/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule QuarianStrings : Quarian Family
{
    meta:
        description = "Quarian Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}

rule QuarianCode : Quarian Family 
{
    meta:
        description = "Quarian code features"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
    
    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
    
    condition:
        any of them
}

rule Quarian : Family
{
    meta:
        description = "Quarian"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        QuarianCode or QuarianStrings
}





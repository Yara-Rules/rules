/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"

/* APTAnthemDeepPanda  */

rule Anthem_DeepPanda_sl_txt_packed
{

    meta:
        description = "Anthem Hack Deep Panda - ScanLine sl-txt-packed"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "ffb1d8ea3039d3d5eb7196d27f5450cac0ea4f34"

    strings:
        $s0 = "Command line port scanner" fullword wide
        $s1 = "sl.exe" fullword wide
        $s2 = "CPports.txt" fullword ascii
        $s3 = ",GET / HTTP/.}" fullword ascii
        $s4 = "Foundstone Inc." fullword wide
        $s9 = " 2002 Foundstone Inc." fullword wide
        $s15 = ", Inc. 2002" fullword ascii
        $s20 = "ICMP Time" fullword ascii

    condition:
        all of them
}

rule Anthem_DeepPanda_lot1
{

    meta:
        description = "Anthem Hack Deep Panda - lot1.tmp-pwdump"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "5d201a0fb0f4a96cefc5f73effb61acff9c818e1"

    strings:
        $s0 = "Unable to open target process: %d, pid %d" fullword ascii
        $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
        $s2 = "Target: Failed to load SAM functions." fullword ascii
        $s5 = "Error writing the test file %s, skipping this share" fullword ascii
        $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
        $s8 = "Service start failed: %d (%s/%s)" fullword ascii
        $s12 = "PwDump.exe" fullword ascii
        $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
        $s14 = ":\\\\.\\pipe\\%s" fullword ascii
        $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
        $s16 = "dump logon session" fullword ascii
        $s17 = "Timed out waiting to get our pipe back" fullword ascii
        $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
        $s20 = "%s\\%s.exe" fullword ascii

    condition:
        10 of them
}

rule Anthem_DeepPanda_htran_exe
{

    meta:
        description = "Anthem Hack Deep Panda - htran-exe"
        author = "Florian Roth"
        date = "2015/02/08"
        hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"

    strings:
        $s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
        $s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
        $s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
        $s3 = "[SERVER]connection to %s:%d error" fullword ascii
        $s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s5 = "[-] ERROR: Must supply logfile name." fullword ascii
        $s6 = "[-] There is a error...Create a new connection." fullword ascii
        $s7 = "[+] Accept a Client on port %d from %s" fullword ascii
        $s8 = "======================== htran V%s =======================" fullword ascii
        $s9 = "[-] Socket Listen error." fullword ascii
        $s10 = "[-] ERROR: open logfile" fullword ascii
        $s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
        $s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
        $s14 = "Recv %5d bytes from %s:%d" fullword ascii
        $s15 = "[+] OK! I Closed The Two Socket." fullword ascii
        $s16 = "[+] Waiting another Client on port:%d...." fullword ascii
        $s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
        $s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii

    condition:
        10 of them
}

rule Anthem_DeepPanda_Trojan_Kakfum
{

    meta:
        description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
        author = "Florian Roth"
        date = "2015/02/08"
        hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
        hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"

    strings:
        $s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
        $s1 = "%s\\sqlsrv32.dll" fullword ascii
        $s2 = "%s\\sqlsrv64.dll" fullword ascii
        $s3 = "%s\\%d.tmp" fullword ascii
        $s4 = "ServiceMaix" fullword ascii
        $s15 = "sqlserver" fullword ascii

    condition:
        all of them
}

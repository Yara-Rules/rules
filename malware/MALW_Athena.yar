/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule AthenaHTTP
{
    
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-09"
        description = "Identify Athena HTTP"
    
    strings:
        $s1 = "%s(%s)"
        $s2 = "type:on_exec"
        $s3 = "uid:%s"
        $s4 = "priv:%s"
        $s5 = "arch:x%s"
        $s6 = "gend:%s"
        $s7 = "cores:%i"
        $s8 = "ver:%s"
        $s9 = "net:%s"
    
    condition:
        all of them
}


rule AthenaHTTP_v2 
{
    
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        description = "Athena HTTP identification"
        source = "https://github.com/arbor/yara/blob/master/athena.yara"

    strings:
        $fmt_str1="|type:on_exec|uid:%s|priv:%s|arch:x%s|gend:%s|cores:%i|os:%s|ver:%s|net:%s|"
        $fmt_str2="|type:repeat|uid:%s|ram:%ld|bk_killed:%i|bk_files:%i|bk_keys:%i|busy:%s|"
        $cmd1 = "filesearch.stop"
        $cmd2 = "rapidget"
        $cmd3 = "layer4."
        $cmd4 = "slowloris"
        $cmd5 = "rudy"
   
    condition:
        all of ($fmt_str*) and 3 of ($cmd*)
}

rule AthenaIRC 
{

    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        description = "Athena IRC v1.8.x, 2.x identification"
        source = "https://github.com/arbor/yara/blob/master/athena.yara"

    strings:
        $cmd1 = "ddos." fullword
        $cmd2 = "layer4." fullword
        $cmd3 = "war." fullword
        $cmd4 = "smartview" fullword
        $cmd5 = "ftp.upload" fullword
        $msg1 = "%s %s :%s LAYER4 Combo Flood: Stopped"
        $msg2 = "%s %s :%s IRC War: Flood started [Type: %s | Target: %s]"
        $msg3 = "%s %s :%s FTP Upload: Failed"
        $msg4 = "Athena v2"
        $msg5 = "%s %s :%s ECF Flood: Stopped [Total Connections: %ld | Rate: %ld Connections/Second]"
        // v1 strs
        $amsg1 = "ARME flood on %s/%s:%i for %i seconds [Host confirmed vulnerable"
        $amsg2 = " Rapid HTTP Combo flood on %s:%i for %i seconds"
        $amsg3 = "Began flood: %i connections every %i ms to %s:%i"
        $amsg4 = "IPKiller>Athena"
        $amsg5 = "Athena=Shit!"
        $amsg6 = "Athena-v1"
        $amsg7 = "BTC wallet.dat file found"
        $amsg8 = "MineCraft lastlogin file found"
        $amsg9 = "Process '%s' was found and scheduled for deletion upon next reboot"
        $amsg10 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)"
        // Athena-v1.8.3
        $amsg11 = "Rapid Connect/Disconnect"
        $amsg12 = "BTC wallet.dat found,"
        // v1 cmds
        $acmd1 = ":!arme"
        $acmd2 = ":!openurl"
        $acmd3 = ":!condis"
        $acmd4 = ":!httpcombo"
        $acmd5 = ":!urlblock"
        $acmd6 = ":!udp"
        $acmd7 = ":!btcwallet"
   
    condition:
        (all of ($cmd*) and 3 of ($msg*)) or (5 of ($amsg*) and 5 of ($acmd*))
}

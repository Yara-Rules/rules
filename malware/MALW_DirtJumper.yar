/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule DirtJumper_drive
{
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        date = "2013-08-26"
        description = "Identify first version of drive DDoS malware"
        source = "https://github.com/arbor/yara/blob/master/drive.yara"
    strings:
        $cmd1 = "-get" fullword
        $cmd2 = "-ip" fullword
        $cmd3 = "-ip2" fullword
        $cmd4 = "-post1" fullword
        $cmd5 = "-post2" fullword
        $cmd6 = "-udp" fullword
        $str1 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]&username=[50]&vb_login_username=[50]&vb_login_md5password=[50]"
        $str2 = "-timeout" fullword
        $str3 = "-thread" fullword
        $str4 = " Local; ru) Presto/2.10.289 Version/"
        $str5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT"
        $newver1 = "-icmp"
        $newver2 = "<xmp>"
    condition:
        4 of ($cmd*) and all of ($str*) and not any of ($newver*)
}


rule DirtJumper_drive2
{
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        date = "2013-08-26"
        description = "Identify newer version of drive DDoS malware"
        source = "https://github.com/arbor/yara/blob/master/drive2.yara"
    strings:
        $cmd1 = "-get" fullword
        $cmd2 = "-ip" fullword
        $cmd3 = "-ip2" fullword
        $cmd4 = "-post1" fullword
        $cmd5 = "-post2" fullword
        $cmd6 = "-udp" fullword
        $str1 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]&username=[50]&vb_login_username=[50]&vb_login_md5password=[50]"
        $str2 = "-timeout" fullword
        $str3 = "-thread" fullword
        $str4 = " Local; ru) Presto/2.10.289 Version/"
        $str5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT"
        $newver1 = "-icmp"
        $newver2 = "-byte"
        $newver3 = "-long"
        $newver4 = "<xmp>"
    condition:
        4 of ($cmd*) and all of ($str*) and all of ($newver*)
}


rule DirtJumper_drive3
{
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        date = "2014-03-17"
        description = "Identify version of Drive DDoS malware using compromised sites"
        source = "https://github.com/arbor/yara/blob/master/drive3.yara"
    strings:
        $cmd1 = "-get" fullword
        $cmd2 = "-ip" fullword
        $cmd3 = "-ip2" fullword
        $cmd4 = "-post1" fullword
        $cmd5 = "-post2" fullword
        $cmd6 = "-udp" fullword
        $str1 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]&username=[50]&vb_login_username=[50]&vb_login_md5password=[50]"
        $str2 = "-timeout" fullword
        $str3 = "-thread" fullword
        $str4 = " Local; ru) Presto/2.10.289 Version/"
        $str5 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT"
        $newver1 = "-icmp"
        $newver2 = "-byte"
        $newver3 = "-long"
        $drive3 = "99=1"
    condition:
        4 of ($cmd*) and all of ($str*) and all of ($newver*) and $drive3
}

/*
    YARA Rule Set for MalConfScan
    Author: JPCERT/CC Incident Response Group
    Date: 2019/04/22
    Reference: https://github.com/JPCERTCC/MalConfScan/
*/

rule TSCookie {
          meta:
            description = "detect TSCookie in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
            hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
            $b1 = { 68 D4 08 00 00 }

          condition: all of them
}

rule TSC_Loader {
          meta:
            description = "detect TSCookie Loader in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" wide
            $b1 = { 68 78 0B 00 00 }

          condition: all of them
}

rule CobaltStrike {
          meta:
            description = "detect CobaltStrike Beacon in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
            hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
            hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

          strings:
            $v1 = { 73 70 72 6E 67 00 }
            $v2 = { 69 69 69 69 69 69 69 69 }

          condition: all of them
}

rule RedLeaves {
          meta:
            description = "detect RedLeaves in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory block scan"
            reference = "https://blogs.jpcert.or.jp/en/2017/05/volatility-plugin-for-detecting-redleaves-malware.html"
            hash1 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

          strings:
            $v1 = "red_autumnal_leaves_dllmain.dll"
            $b1 = { FF FF 90 00 }

          condition: $v1 and $b1 at 0
}

rule Himawari {
          meta:
            description = "detect Himawari(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
            hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

          strings:
            $h1 = "himawariA"
            $h2 = "himawariB"
            $h3 = "HimawariDemo"

          condition: all of them
}

rule Lavender {
          meta:
            description = "detect Lavender(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

          strings:
            $a1 = { C7 ?? ?? 4C 41 56 45 }
            $a2 = { C7 ?? ?? 4E 44 45 52 }

          condition: all of them
}

rule Armadill {
          meta:
            description = "detect Armadill(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $a1 = { C7 ?? ?? 41 72 6D 61 }
            $a2 = { C7 ?? ?? 64 69 6C 6C }

          condition: all of them
}

rule zark20rk {
          meta:
            description = "detect zark20rk(a variant of RedLeaves) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

          strings:
            $a1 = { C7 ?? ?? 7A 61 72 6B }
            $a2 = { C7 ?? ?? 32 30 72 6B }

          condition: all of them
}

rule Ursnif {
          meta:
            description = "detect Ursnif(a.k.a. Dreambot, Gozi, ISFB) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "0207c06879fb4a2ddaffecc3a6713f2605cbdd90fc238da9845e88ff6aef3f85"
            hash2 = "ff2aa9bd3b9b3525bae0832d1e2b7c6dfb988dc7add310088609872ad9a7e714"
            hash3 = "1eca399763808be89d2e58e1b5e242324d60e16c0f3b5012b0070499ab482510"

          strings:
            $a1 = "soft=%u&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
            $b1 = "client.dll" fullword
            $c1 = "version=%u"
            $c2 = "user=%08x%08x%08x%08x"
            $c3 = "server=%u"
            $c4 = "id=%u"
            $c5 = "crc=%u"
            $c6 = "guid=%08x%08x%08x%08x"
            $c7 = "name=%s"
            $c8 = "soft=%u"
            $d1 = "%s://%s%s"
            $d2 = "PRI \x2A HTTP/2.0"
            $e1 = { A1 ?? ?? ?? 00 35 E7 F7 8A 40 50 }
            $e2 = { 56 56 56 6A 06 5? FF ?? ?? ?? ?? 00 }
            $f1 = { 56 57 BE ?? ?? ?? ?? 8D ?? ?? A5 A5 A5 }
            $f2 = { 35 8F E3 B7 3F }
            $f3 = { 35 0A 60 2E 51 }

         condition: $a1 or ($b1 and 3 of ($c*)) or (5 of ($c*)) or ($b1 and all of ($d*)) or all of ($e*) or all of ($f*)
}

rule Emotet {
          meta:
            description = "detect Emotet in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v4a = { BB 00 C3 4C 84 }
            $v4b = { B8 00 C3 CC 84 }
            $v5a = { 69 01 6D 4E C6 41 05 39 30 00 00 }
            $v5b = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 }

          condition: ($v4a and $v4b) or $v5a or $v5b
}

rule SmokeLoader {
          meta:
            description = "detect SmokeLoader in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://www.cert.pl/en/news/single/dissecting-smoke-loader/"

          strings:
            $a1 = { B8 25 30 38 58 }
            $b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 }
            $c1 = { C7 ?? ?? ?? 25 73 25 73 }

          condition: $a1 and $b1 and $c1
}

rule Datper {
          meta:
            description = "detect Datper in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"

          strings:
            $a1 = { E8 03 00 00 }
            $b1 = "|||"
            $c1 = "Content-Type: application/x-www-form-urlencoded"
            $push7530h64 = { C7 C1 30 75 00 00 }
            $push7530h = { 68 30 75 00 00 }

          condition: $a1 and $b1 and $c1 and ($push7530h64 or $push7530h)
}

rule PlugX {
          meta:
            description = "detect PlugX in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = { 47 55 4c 50 00 00 00 00 }
            $v2a = { 68 40 25 00 00 }
            $v2c = { 68 58 2D 00 00 }
            $v2b = { 68 a0 02 00 00 }
            $v2d = { 68 a4 36 00 00 }
            $v2e = { 8D 46 10 68 }
            $v2f = { 68 24 0D 00 00 }
            $v2g = { 68 a0 02 00 00 }
            $v2h = { 68 e4 0a 00 00 }
            $enc1 = { C1 E? 03 C1 E? 07 2B ?? }
            $enc2 = { 32 5? ?? 81 E? ?? ?? 00 00 2A 5? ?? 89 ?? ?? 32 ?? 2A ?? 32 5? ?? 2A 5? ?? 32 }
            $enc3 = { B? 33 33 33 33 }
            $enc4 = { B? 44 44 44 44 }
         condition: $v1 at 0 or ($v2a and $v2b and $enc1) or ($v2c and $v2b and $enc1) or ($v2d and $v2b and $enc2) or ($v2d and $v2e and $enc2) or ($v2f and $v2g and $enc3 and $enc4) or ($v2h and $v2g and $enc3 and $enc4)
}

rule Ramnit {
          meta:
            description = "detect Ramnit"
            author = "nazywam"
            module = "ramnit"
            reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"

          strings:
            $guid = "{%08X-%04X-%04X-%04X-%08X%04X}"
            $md5_magic_1 = "15Bn99gT"
            $md5_magic_2 = "1E4hNy1O"
            $init_dga = { C7 ?? ?? ?? ?? ?? FF FF FF FF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 75 ?? }
            $xor_secret = { 8A ?? ?? 32 ?? 88 ?? 4? 4? E2 ?? }
            $init_function = { FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 }
            $dga_rand_int = { B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 }
            $cookies = "cookies4.dat"
            $s3 = "pdatesDisableNotify"
            $get_domains = { a3 [4] a1 [4] 80 3? 00 75 ?? c7 05 [4] ff ff ff ff ff 35 [4] ff 35 [4] ff 35 [4] e8 }
            $add_tld = { 55 8B EC  83 ?? ?? 57 C7 ?? ?? 00 00 00 00 B? ?? ?? ?? ?? 8B ?? ?? 3B ?? ?? 75 ?? 8B ?? }
            $get_port = { 90 68 [4] 68 [4] FF 35 [4] FF 35 [4] E8 [4] 83 }

          condition: $init_dga and $init_function and 2 of ($guid, $md5_magic_*, $cookies, $s3) and any of ( $get_port, $add_tld, $dga_rand_int, $get_domains, $xor_secret)
}

rule Hawkeye {
          meta:
            description = "detect HawkEye in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $hawkstr1 = "HawkEye Keylogger" wide
            $hawkstr2 = "Dear HawkEye Customers!" wide
            $hawkstr3 = "HawkEye Logger Details:" wide

          condition: all of them
}

rule Lokibot {
          meta:
            description = "detect Lokibot in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "6f12da360ee637a8eb075fb314e002e3833b52b155ad550811ee698b49f37e8c"

          strings:
            $des3 = { 68 03 66 00 00 }
            $param = "MAC=%02X%02X%02XINSTALL=%08X%08X"
            $string = { 2d 00 75 00 00 00 46 75 63 6b 61 76 2e 72 75 00 00}

          condition: all of them
}

rule Bebloh {
          meta:
            description = "detect Bebloh(a.k.a. URLZone) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $crc32f = { b8 EE 56 0b ca }
            $dga = "qwertyuiopasdfghjklzxcvbnm123945678"
            $post1 = "&vcmd="
            $post2 = "?tver="

          condition: all of them
}

rule xxmm {
          meta:
            description = "detect xxmm in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "setupParameter:"
            $v2 = "loaderParameter:"
            $v3 = "parameter:"

          condition: all of them
}

rule Azorult {
          meta:
            description = "detect Azorult in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
            $v2 = "http://ip-api.com/json"
            $v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

          condition: all of them
}

rule PoisonIvy {
           meta:
            description = "detect PoisonIvy in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $a1 = { 0E 89 02 44 }
            $b1 = { AD D1 34 41 }
            $c1 = { 66 35 20 83 66 81 F3 B8 ED }

          condition: all of them
}

rule netwire {
           meta:
            description = "detect netwire in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "HostId-%Rand%"
            $v2 = "mozsqlite3"
            $v3 = "[Scroll Lock]"
            $v4 = "GetRawInputData"
            $ping = "ping 192.0.2.2"
            $log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

          condition: ($v1) or ($v2 and $v3 and $v4) or ($ping and $log)
}

rule Nanocore {
          meta:
            description = "detect Nanocore in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "NanoCore Client"
            $v2 = "PluginCommand"
            $v3 = "CommandType"

          condition: all of them
}

rule Formbook {
          meta:
            description = "detect Formbook in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $sqlite3step = { 68 34 1c 7b e1 }
            $sqlite3text = { 68 38 2a 90 c5 }
            $sqlite3blob = { 68 53 d8 7f 8c }

          condition: all of them
}

rule Agenttesla_type1 {
          meta:
            description = "detect Agenttesla in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
            $atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
            $sqlitestr = "Not a valid SQLite 3 Database File" wide
          condition: all of them
}

rule Agenttesla_type2 {
          meta:
            description = "detect Agenttesla in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"
            hash1 = "670a00c65eb6f7c48c1e961068a1cb7fd3653bd29377161cd04bf15c9d010da2 "

          strings:
            $type2db1 = "1.85 (Hash, version 2, native byte-order)" wide
            $type2db2 = "Unknow database format" wide
            $type2db3 = "SQLite format 3" wide
          condition: all of them
}

rule Noderat {
          meta:
            description = "detect Noderat in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"

          strings:
            $config = "/config/app.json"
            $key = "/config/.regeditKey.rc"
            $message = "uninstall error when readFileSync: "

          condition: all of them
}

rule Njrat2 {
          meta:
            description = "detect njRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

          strings:
            $reg = "SEE_MASK_NOZONECHECKS" wide fullword
            $msg = "Execute ERROR" wide fullword
            $ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword
          condition: all of them
}

rule Trickbot {
          meta:
            description = "detect TrickBot in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "2153be5c6f73f4816d90809febf4122a7b065cbfddaa4e2bf5935277341af34c"

          strings:
            $tagm1 = "<mcconf><ver>" wide
            $tagm2 = "</autorun></mcconf>" wide
            $tagc1 = "<moduleconfig><autostart>" wide
            $tagc2 = "</autoconf></moduleconfig>" wide
            $tagi1 = "<igroup><dinj>" wide
            $tagi2 = "</dinj></igroup>" wide
            $tags1 = "<servconf><expir>" wide
            $tags2 = "</plugins></servconf>" wide
            $tagl1 = "<slist><sinj>" wide
            $tagl2 = "</sinj></slist>" wide
          condition: all of ($tagm*) or all of ($tagc*) or all of ($tagi*) or all of ($tags*) or all of ($tagl*)
}

rule Remcos {
          meta:
            description = "detect Remcos in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "7d5efb7e8b8947e5fe1fa12843a2faa0ebdfd7137582e5925a0b9c6a9350b0a5"

          strings:
            $remcos = "Remcos" ascii fullword
            $url = "Breaking-Security.Net" ascii fullword
            $resource = "SETTINGS" wide fullword
          condition:  all of them
}

rule Quasar {
          meta:
            description = "detect Remcos in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

          strings:
            $quasarstr1 = "Client.exe" wide
            $quasarstr2 = "({0}:{1}:{2})" wide
            $class = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 80 }
          condition: all of them
}

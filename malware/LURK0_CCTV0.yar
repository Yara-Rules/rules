rule LURK0Header : Family LURK0 {
meta:
description = "5 char code for LURK0"
author = "Katie Kleemola"
last_updated = "07-21-2014"

strings:
$ = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }

condition:
any of them
}

rule CCTV0Header : Family CCTV0 {
meta:
description = "5 char code for LURK0"
author = "Katie Kleemola"
last_updated = "07-21-2014"

strings:
//if its just one char a time
$ = { C6 [5] 43 C6 [5] 43 C6 [5] 54 C6 [5] 56 C6 [5] 30 }
// bit hacky but for when samples dont just simply mov 1 char at a time
$ = { B0 43 88 [3] 88 [3] C6 [3] 54 C6 [3] 56 [0-12] (B0 30 | C6 [3] 30) }

condition:
any of them
}

rule SharedStrings : Family {
meta:
description = "Internal names found in LURK0/CCTV0 samples"
author = "Katie Kleemola"
last_updated = "07-22-2014"

strings:
// internal names
$i1 = "Butterfly.dll"
$i2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
$i3 = "ETClientDLL"

// dbx
$d1 = "\\DbxUpdateET\\" wide
$d2 = "\\DbxUpdateBT\\" wide
$d3 = "\\DbxUpdate\\" wide

// other folders
$mc1 = "\\Micet\\"

// embedded file names
$n1 = "IconCacheEt.dat" wide
$n2 = "IconConfigEt.dat" wide


 
$m1 = "\x00\x00ERXXXXXXX\x00\x00" wide
$m2 = "\x00\x00111\x00\x00" wide
$m3 = "\x00\x00ETUN\x00\x00" wide
$m4 = "\x00\x00ER\x00\x00" wide

condition:
any of them //todo: finetune this

}

rule LURK0 : Family LURK0 {

meta:
description = "rule for lurk0"
author = "Katie Kleemola"
last_updated = "07-22-2014"

condition:
LURK0Header and SharedStrings

}

rule CCTV0 : Family CCTV0 {

meta:
description = "rule for cctv0"
author = "Katie Kleemola"
last_updated = "07-22-2014"

condition:
CCTV0Header and SharedStrings

}

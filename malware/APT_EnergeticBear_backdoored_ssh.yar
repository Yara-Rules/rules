rule Backdoored_ssh {
meta:
author = "Kaspersky"
reference = "https://securelist.com/energetic-bear-crouching-yeti/85345/"
actor = "Energetic Bear/Crouching Yeti"
strings:
$a1 = "OpenSSH"
$a2 = "usage: ssh"
$a3 = "HISTFILE"
condition:
uint32(0) == 0x464c457f and filesize<1000000 and all of ($a*)
}

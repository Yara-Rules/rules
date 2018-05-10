rule crime_ransomware_windows_GPGQwerty: crime_ransomware_windows_GPGQwerty

{

meta:

author = "McAfee Labs"

description = "Detect GPGQwerty ransomware"

reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"

strings:

$a = "gpg.exe –recipient qwerty  -o"

$b = "%s%s.%d.qwerty"

$c = "del /Q /F /S %s$recycle.bin"

$d = "cryz1@protonmail.com"

condition:

all of them

}

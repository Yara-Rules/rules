rule Adwind
{
meta:
        author="Asaf Aprozper, asafa AT minerva-labs.com"
        description = "Adwind RAT"
        reference = "https://minerva-labs.com/post/adwind-and-other-evasive-java-rats"
        last_modified = "2017-06-25"
strings:
        $a0 = "META-INF/MANIFEST.MF"
        $a1 = /Main(\$)Q[0-9][0-9][0-9][0-9]/
        $PK = "PK"
condition:
        $PK at 0 and $a0 and $a1
}

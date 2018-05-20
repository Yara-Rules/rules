/*
 * DESCRIPTION: Yara rules to match the known binary components of the HatMan
 *              malware targeting Triconex safety controllers. Any matching
 *              components should hit using the "hatman" rule in addition to a
 *              more specific "hatman_*" rule.
 * AUTHOR:      DHS/NCCIC/ICS-CERT
 */

/* Globally only look at small files. */

private global rule hatman_filesize : hatman {
    condition:
        filesize < 100KB
}

/* Private rules that are used at the end in the public rules. */

private rule hatman_setstatus : hatman {
    strings:
        $preset     = { 80 00 40 3c  00 00 62 80  40 00 80 3c  40 20 03 7c 
                        ?? ?? 82 40  04 00 62 80  60 00 80 3c  40 20 03 7c 
                        ?? ?? 82 40  ?? ?? 42 38                           }
    condition:
        $preset
}
private rule hatman_memcpy : hatman {
    strings:
        $memcpy_be  = { 7c a9 03 a6  38 84 ff ff  38 63 ff ff  8c a4 00 01 
                        9c a3 00 01  42 00 ff f8  4e 80 00 20              }
        $memcpy_le  = { a6 03 a9 7c  ff ff 84 38  ff ff 63 38  01 00 a4 8c
                        01 00 a3 9c  f8 ff 00 42  20 00 80 4e              }
    condition:
        $memcpy_be or $memcpy_le
}
private rule hatman_dividers : hatman {
    strings:
        $div1       = { 9a 78 56 00 }
        $div2       = { 34 12 00 00 }
    condition:
        $div1 and $div2
}
private rule hatman_nullsub : hatman {
    strings:
        $nullsub     = { ff ff 60 38  02 00 00 44  20 00 80 4e }
    condition:
        $nullsub
}
private rule hatman_origaddr : hatman {
    strings:
        $oaddr_be   = { 3c 60 00 03  60 63 96 f4  4e 80 00 20 }
        $oaddr_le   = { 03 00 60 3c  f4 96 63 60  20 00 80 4e }
    condition:
        $oaddr_be or $oaddr_le
}
private rule hatman_origcode : hatman {
    strings:
        $ocode_be   = { 3c 00 00 03  60 00 a0 b0  7c 09 03 a6  4e 80 04 20 }
        $ocode_le   = { 03 00 00 3c  b0 a0 00 60  a6 03 09 7c  20 04 80 4e }
    condition:
        $ocode_be or $ocode_le
}
private rule hatman_mftmsr : hatman {
    strings:
        $mfmsr_be   = { 7c 63 00 a6 }
        $mfmsr_le   = { a6 00 63 7c }
        $mtmsr_be   = { 7c 63 01 24 }
        $mtmsr_le   = { 24 01 63 7c }
    condition:
        ($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le)
}
private rule hatman_loadoff : hatman {
    strings:
        $loadoff_be = { 80 60 00 04  48 00 ?? ??  70 60 ff ff  28 00 00 00
                        40 82 ?? ??  28 03 00 00  41 82 ?? ??              }
        $loadoff_le = { 04 00 60 80  ?? ?? 00 48  ff ff 60 70  00 00 00 28 
                        ?? ?? 82 40  00 00 03 28  ?? ?? 82 41              }
    condition:
        $loadoff_be or $loadoff_le
}
private rule hatman_injector_int : hatman {
    condition:
        hatman_memcpy and hatman_origaddr and hatman_loadoff
}
private rule hatman_payload_int : hatman {
    condition:
        hatman_memcpy and hatman_origcode and hatman_mftmsr
}

/* Actual public rules to match using the private rules. */

rule hatman_compiled_python : hatman {
    condition:
        hatman_nullsub and hatman_setstatus and hatman_dividers
}
rule hatman_injector : hatman {
    condition:
        hatman_injector_int and not hatman_payload_int
}
rule hatman_payload : hatman {
    condition:
        hatman_payload_int and not hatman_injector_int
}
rule hatman_combined : hatman {
    condition:
        hatman_injector_int and hatman_payload_int and hatman_dividers
}
rule hatman : hatman {
    meta:
        author = "DHS/NCCIC/ICS-CERT"
        description = "Matches the known samples of the HatMan malware."
    condition:
        hatman_compiled_python or hatman_injector or hatman_payload
            or hatman_combined
}

/*
    Author: Jaume Martin
    Date: 26/04/2017
    Description: This finds the magics on dump files, like raw dd image. This can though false positives.
*/

rule contains_win_64_mem_dump: DMP
{
    meta:
        author = "Jaume Martin"
        file_info = "Windows 64-bit memory dump"

    strings:
        $a = {50 41 47 45 44 55 36 34}

    condition:
       $a
}

rule contains_win_32_mem_dump: DMP
{
    meta:
        author = "Jaume Martin"
        file_info = "Windows 32-bit memory dump"

    strings:
        $a = {50 41 47 45 44 55 4D 50}

    condition:
       $a
}

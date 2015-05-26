/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule NionSpy
{
meta:
description = "Triggers on old and new variants of W32/NionSpy file infector"
reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
strings:
$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
$variant2013_string = "%s?cstorage=shell&comp=%s"
condition:
uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($variant*)
}

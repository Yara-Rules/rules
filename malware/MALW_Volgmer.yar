rule volgmer
{
meta:
    description = "Malformed User Agent"
    ref = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
strings:
    $s = "Mozillar/"
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $s
}

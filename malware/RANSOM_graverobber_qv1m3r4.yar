rule MAL_Graverobber_Qv1m3r4_Python
{
    meta:
        family      = "Graverobber"
        variant     = "qv1m3r4.py"
        description = "Detects qv1m3r4 variant"
        author      = "rf-peixoto"
        reference   = "github.com/rf-peixoto/Graverobber"
        confidence  = "high"

    strings:
        $s_egg1      = "egg_{0}.txt" ascii
        $s_nodesig   = "Node Signature: {0}\\n" ascii
        $s_qv        = "qv1m3r4" ascii
        $s_note_1    = "Send a message to our@email.com to get in touch." ascii
        $s_note_url  = "file://{0}/egg_{1}.txt" ascii
        $s_aes       = "from AesEverywhere import aes256" ascii

    condition:
        $s_qv and $s_egg1 and $s_nodesig
        and $s_aes and any of ($s_note_1, $s_note_url)
}

rule MAL_Graverobber_RiverLethe_Python
{
    meta:
        family      = "Graverobber"
        variant     = "river_lethe.py"
        description = "Detects River Lethe variant"
        author      = "rf-peixoto"
        reference   = "github.com/rf-peixoto/Graverobber"
        confidence  = "high"

    strings:
        $s_title   = "River Lethe" ascii
        $s_msg1    = "Everything you had is lost in oblivion." ascii
        $s_msg2    = "Send a signal to EMAIL and we will to guide you in this journey." ascii
        $s_btc     = "BTC Address" ascii
        $s_blox    = "from bloxplorer import bitcoin_explorer" ascii
        $s_form1   = "http://127.0.0.1/file_form.php" ascii
        $s_form2   = "http://{0}.com/file_form.php" ascii
        $s_ping    = "ping -c 1 " ascii

    condition:
        all of ($s_title, $s_msg1, $s_msg2)
        and $s_blox and $s_btc
        and any of ($s_form1, $s_form2)
        and $s_ping and $s_fileup
}

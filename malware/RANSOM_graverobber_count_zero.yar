rule MAL_Graverobber_CountZero_Python
{
    meta:
        family      = "Graverobber"
        variant     = "countzero.py"
        description = "Detects CountZero variant"
        author      = "rf-peixoto"
        reference   = "github.com/rf-peixoto/Graverobber"
        confidence  = "high"

    strings:
        $s_readme    = "CountZero.README.txt" ascii
        $s_readmeurl = "file://{0}/CountZero.README.txt" ascii
        $s_btc       = "BTC Address" ascii
        $s_blox      = "from bloxplorer import bitcoin_explorer" ascii
        $s_form1     = "http://127.0.0.1/file_form.php" ascii
        $s_form2     = "http://{0}.com/file_form.php" ascii
        $s_ping      = "ping -c 1 " ascii
        $s_fileup    = "fileToUpload" ascii

    condition:
        // Ransom note + BTC + C2 infra + bloxplorer
        $s_readme and $s_btc
        and any of ($s_form1, $s_form2)
        and $s_blox and $s_fileup and $s_ping
}

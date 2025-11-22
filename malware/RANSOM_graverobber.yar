rule MAL_Graverobber_Main_Python
{
    meta:
        family      = "Graverobber"
        variant     = "graverobber.py"
        description = "Detects Graverobber main Python ransomware payload"
        author      = "rf-peixoto"
        reference   = "github.com/rf-peixoto/Graverobber"
        confidence  = "high"

    strings:
        $s_title      = "The Graverobber - DO NOT CLOSE THIS WINDOW!" ascii
        $s_visit      = "You have been visited by the Graverobber. " ascii
        $s_nodefile   = "node_{0}.txt" ascii
        $s_nodesig    = "Node Signature: {0}" ascii
        $s_aes        = "from AesEverywhere import aes256" ascii
        $s_bloxplorer = "from bloxplorer import bitcoin_explorer" ascii
        $s_file_form  = "http://{0}.com/file_form.php" ascii
        $s_ping       = "ping -c 1 " ascii

    condition:
        // Require strong family markers: UI text + crypto + infra pieces
        all of ($s_title, $s_visit, $s_nodefile, $s_nodesig)
        and $s_aes and $s_bloxplorer and $s_file_form
}

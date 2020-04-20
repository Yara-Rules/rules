

rule almashreq_agent_dotnet : almashreq_agent_dotnet
{
    meta:
        description = "Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq"
	author = "J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!"
        date = "2019-05-12"
        reference1 = "https://twitter.com/JayTHL/status/1127334608142503936"
        reference2 = "https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details"
        reference3 = "https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection"
        reference4 = "https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection"
        reference5 = "https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection" 
        maltype = "agent"
	filetype = "memory"

    strings:
        $s01 = "WriteElementString(@\"PCName\"," wide
        $s02 = "WriteElementString(@\"Command\"," wide
        $s03 = "WriteElementStringRaw(@\"commandID\"," wide
	$s04 = /^Try Run$/ wide
        $s05 = " is running in PC :" wide
        $s06 = "SOAPAction: \"http://tempuri.org/Set\"" wide
        $s07 = "Try Run</obj><name>" wide
        $s08 = "Disable</obj><name>" wide
        $s09 = "http://tempuri.org/" wide

 	condition: 
 		7 of them
}


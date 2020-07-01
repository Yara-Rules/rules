rule RAT_Orcus 
{

    meta:
        author = " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam"
        date = "2017/01"
        reference = "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"
        version = 1
        maltype = "RAT"
        filetype = "memory"

    strings:
        $text01 = "Orcus.CommandManagement"
        $text02 = "Orcus.Commands."
        $text03 = "Orcus.Config."
        $text04 = "Orcus.Connection."
        $text05 = "Orcus.Core."
        $text06 = "Orcus.exe"
        $text07 = "Orcus.Extensions."
        $text08 = "Orcus.InstallationPromptForm"
        $text09 = "Orcus.MainForm."
        $text10 = "Orcus.Native."
        $text11 = "Orcus.Plugins."
        $text12 = "orcus.plugins.dll"
        $text13 = "Orcus.Properties."
        $text14 = "Orcus.Protection."
        $text15 = "Orcus.Share."
        $text16 = "Orcus.Shared"
        $text17 = "Orcus.StaticCommands"
        $text18 = "Orcus.Utilities."
        $text19 = "\\Projects\\Orcus\\Source\\Orcus."
        $text20 = ".orcus.plugins.dll.zip"
        $text21 = ".orcus.shared.dll.zip"
        $text22 = ".orcus.shared.utilities.dll.zip"
        $text23 = ".orcus.staticcommands.dll.zip"
        $text24 = "HvncCommunication"
        $text25 = "HvncAction"
        $text26 = "hvncDesktop"
        $text27 = ".InstallationPromptForm"
        $text28 = "RequestKeyLogCommand"
        $text29 = "get_KeyLogFile"
        $text30 = "LiveKeyloggerCommand"
        $text31 = "ORCUS.STATICCOMMANDS, VERSION="
        $text32 = "PrepareOrcusFileToRemove"
        $text33 = "ConvertFromOrcusValueKind"

    condition:
        13 of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ransom_comodosec_mrcr1 {

        meta:
                author = " J from THL <j@techhelplist.com>"
                date = "2017/01"
                reference = "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"
                version = 1
                maltype = "Ransomware"
                filetype = "memory"

        strings:
                $text01 = "WebKitFormBoundary"
                $text02 = "Start NetworkScan"
                $text03 = "Start DriveScan"
                $text04 = "Start CryptFiles"
                $text05 = "cmd /c vssadmin delete shadows /all /quiet"
                $text06 = "isAutorun:"
                $text07 = "isNetworkScan:"
                $text08 = "isUserDataLast:"
                $text09 = "isCryptFileNames:"
                $text10 = "isChangeFileExts:"
                $text11 = "isPowerOffWindows:"
                $text12 = "GatePath:"
                $text13 = "GatePort:"
                $text14 = "DefaultCryptKey:"
                $text15 = "UserAgent:"
                $text16 = "Mozilla_"
                $text17 = "On Error Resume Next"
                $text18 = "Content-Disposition: form-data; name=\"uid\""
                $text19 = "Content-Disposition: form-data; name=\"uname\""
                $text20 = "Content-Disposition: form-data; name=\"cname\""
                $regx21 = /\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|/


    condition:
        10 of them
}

/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/* 
  github.com/dfirnotes/rules
  Version 0.0.0
*/

rule Str_Win32_Winsock2_Library
{

    meta:
        author = "@adricnet"
        description = "Match Winsock 2 API library declaration"
        method = "String match"

    strings:
        $ws2_lib = "Ws2_32.dll" nocase
        $wsock2_lib = "WSock32.dll" nocase

    condition:
    (any of ($ws2_lib, $wsock2_lib))
}

rule Str_Win32_Wininet_Library
{
    
    meta:
        author = "@adricnet"
        description = "Match Windows Inet API library declaration"
        method = "String match"
    
    strings:
        $wininet_lib = "WININET.dll" nocase
    
    condition:
    (all of ($wininet*))
}

rule Str_Win32_Internet_API
{
   
    meta:
        author = "@adricnet"
        description = "Match Windows Inet API call"
        method = "String match, trim the As"
   
    strings:
        $wininet_call_closeh = "InternetCloseHandle"
        $wininet_call_readf = "InternetReadFile"
        $wininet_call_connect = "InternetConnect"
        $wininet_call_open = "InternetOpen"

    condition:
        (any of ($wininet_call*))
}

rule Str_Win32_Http_API
{
    meta:
        author = "@adricnet"
        description = "Match Windows Http API call"
        method = "String match, trim the As"
   
    strings:
        $wininet_call_httpr = "HttpSendRequest"
        $wininet_call_httpq = "HttpQueryInfo"
        $wininet_call_httpo = "HttpOpenRequest"
     condition:
        (any of ($wininet_call_http*))
}

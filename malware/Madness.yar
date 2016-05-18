/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule Madness {
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        date = "2014-01-15"
        description = "Identify Madness Pro DDoS Malware"
        source = "https://github.com/arbor/yara/blob/master/madness.yara"
    strings:
        $ua1 = "TW96aWxsYS81LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNS4xOyBlbi1VUzsgcnY6MS44LjAuNSkgR2Vja28vMjAwNjA3MzEgRmlyZWZveC8xLjUuMC41IEZsb2NrLzAuNy40LjE"
        $ua2 = "TW96aWxsYS81LjAgKFgxMTsgVTsgTGludXggMi40LjItMiBpNTg2OyBlbi1VUzsgbTE4KSBHZWNrby8yMDAxMDEzMSBOZXRzY2FwZTYvNi4wMQ=="
        $str1= "document.cookie=" fullword
        $str2 = "[\"cookie\",\"" fullword
        $str3 = "\"realauth=" fullword
        $str4 = "\"location\"];" fullword
        $str5 = "d3Rm" fullword
        $str6 = "ZXhl" fullword
    condition:
        all of them
}
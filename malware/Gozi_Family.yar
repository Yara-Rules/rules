/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule GoziRule : Gozi Family {
meta:
    description = "Win32.Gozi"
    author = "CCN-CERT"
    version = "1.0"
    ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
strings:
    $ = {63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 2D 00 6A 00 6F 00 75 00 72 00 6E 00 61 00 6C 00 00 00 4F 50 45 52 41 2E 45 58 45 00}
condition:
    all of them
}

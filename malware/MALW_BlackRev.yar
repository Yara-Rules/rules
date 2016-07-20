/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.

*/

rule BlackRev
{
   meta:
      author = "Dennis Schwarz"
      date = "2013-05-21"
      description = "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"
      origin = "https://github.com/arbor/yara/blob/master/blackrev.yara"

   strings: 
      $base1 = "http"
      $base2 = "simple"
      $base3 = "loginpost"
      $base4 = "datapost"

      $opt1 = "blackrev"
      $opt2 = "stop"
      $opt3 = "die"
      $opt4 = "sleep"
      $opt5 = "syn"
      $opt6 = "udp"
      $opt7 = "udpdata"
      $opt8 = "icmp"
      $opt9 = "antiddos"
      $opt10 = "range"
      $opt11 = "fastddos"
      $opt12 = "slowhttp"
      $opt13 = "allhttp"
      $opt14 = "tcpdata"
      $opt15 = "dataget"

   condition:
      all of ($base*) and 5 of ($opt*)
}

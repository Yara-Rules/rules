/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule TreasureHunt
  {
    meta:
      author = "Minerva Labs"
      ref ="http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed"
      date = "2016/06"
      maltype = "Point of Sale (POS) Malware"
      filetype = "exe"

    strings:
      $a = "treasureHunter.pdb"
      $b = "jucheck"
      $c = "cmdLineDecrypted"

    condition:
      all of them
}


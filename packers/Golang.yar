/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule go_language_pe
{
   meta:
      description = "Detection for PE compiled Go programming language" 
      date = "2021/8/5"
      author = "Ryan Boyle randomrhythm@rhythmengineering.com"
      filetype = "pe"
      sample1 = "881be95a9632fa44deeeca23e4e19390d600ad817b2f66671d3f21453a16c7b7" //ElectroRAT
      sample2 = "B6E7E3C92501AB1BDB164ACE2C7452B3" //Ekans
      sample3 = "fcf03bf5ef4babce577dd13483391344e957fd2c855624c9f0573880b8cba62e" //Zebrocy
      sample4 = "12b927235ab1a5eb87222ef34e88d4aababe23804ae12dc0807ca6b256c7281c" //ChaChi
      sample5 = "5da2a2ebe9959e6ac21683a8950055309eb34544962c02ed564e0deaf83c9477" //DECAF Ransomware
   strings:
      $go1 = "go.buildid" ascii wide
      $go2 = "go.buildi\\" ascii wide
      $go3 = "Go build ID:" ascii wide
      $go4 = "Go buildinf:"
      $go5 = "runtime.cgo"
      $go6 = "runtime.go"
      $go7 = "GOMAXPRO"
      $str1 = "kernel32.dll" nocase
   condition:
      uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 2 of ($go*) and all of ($str*)
}

rule go_language_elf
{
   meta:
      description = "Detection for Go programming language compiled ELF files"
      date = "2021/8/5"
      author = "Ryan Boyle randomrhythm@rhythmengineering.com"
      sampleLinux1= "14e9b5e214572cb13ff87727d680633f5ee238259043357c94302654c546cad2" //WellMess
      sampleLinux2= "0c395715bfeb8f89959be721cd2f614d2edb260614d5a21e90cc4c142f5d83ad/detection" //BotenaGo
      filetype = "elf"
   strings:
      $goLinux1 = "/Go/src/"
      $goLinux2 = "/golang/src/"
      $GOMAXPROCS1 = "Gomax"
      $GOMAXPROCS2 = "GOMAXPRO"
      $ELFheader = { 7F 45 4C 46 }
   condition:
      $ELFheader and 1 of ($goLinux*) and 1 of ($GOMAXPROCS*)
}
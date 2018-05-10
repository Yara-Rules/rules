
rule sigma_ransomware {

  meta:
    author = "J from THL <j@techhelplist.com>"
    date = "20180509"
    reference1 = "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba"
    reference2 = "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"
    version = 1
    maltype = "Ransomware"
    filetype = "memory"

  strings:
    $a = ".php?"
    $b = "uid="
    $c = "&uname="
    $d = "&os="
    $e = "&pcname="
    $f = "&total="
    $g = "&country="
    $h = "&network="
    $i = "&subid="

  condition:
    all of them
}

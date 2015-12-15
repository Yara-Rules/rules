rule XOR_DDosv1 : DDoS
{
  meta:
    author = "Akamai SIRT"
    description = "Rule to detect XOR DDos infection"
  strings:
    $st0 = "BB2FA36AAA9541F0"
    $st1 = "md5="
    $st2 = "denyip="
    $st3 = "filename="
    $st4 = "rmfile="
    $st5 = "exec_packet"
    $st6 = "build_iphdr"
  condition:
    all of them
}

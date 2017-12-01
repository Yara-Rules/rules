rule XMRIG_Miner
{
	meta:
  ref = "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"
  strings:
    $a1 = "stratum+tcp"
    condition:
    $a1  
}

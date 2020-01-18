import "androguard"

rule Android_DeathRing
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."
		source = "https://blog.lookout.com/blog/2014/12/04/deathring/"

	condition:
		androguard.service(/MainOsService/i) and
        androguard.receiver(/ApkUninstallReceiver/i)
}

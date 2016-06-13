//more info at reversecodes.wordpress.com
rule DMALocker
{
    meta:
    Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
    Author = "SadFud"
    Date = "30/05/2016"
    
    strings:
    $uno = { 41 42 43 58 59 5a 31 31 }
	  $dos = { 21 44 4d 41 4c 4f 43 4b }
	  $tres = { 21 44 4d 41 4c 4f 43 4b 33 2e 30 }
	  $cuatro = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    any of them
    
}

//more info at reversecodes.wordpress.com
rule DMALocker
{
    meta:
    Description = "Deteccion del ransomware DMA Locker desde la version 1.0 a la 4.0"
    ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
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

//More at reversecodes.wordpress.com
rule DMALocker4 {

    meta:
    Description = "Deteccion del ransomware DMA Locker version 4.0"
    ref = "https://blog.malwarebytes.org/threat-analysis/2016/02/dma-locker-a-new-ransomware-but-no-reason-to-panic/"
    Author = "SadFud"
    Date = "30/05/2016"
	Hash = "e3106005a0c026fc969b46c83ce9aeaee720df1bb17794768c6c9615f083d5d1"
    
    strings:
    $clave = { 21 44 4d 41 4c 4f 43 4b 34 2e 30 }
    
    condition:
    $clave 
    
}

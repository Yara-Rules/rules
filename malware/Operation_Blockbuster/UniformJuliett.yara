rule UniformJuliett
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd03000_1a6f62e1630d512c3b67bfdbff26270177585c82802ffa834b768ff47be0a008.bin"

	strings:
		/*
			56                 push    esi             ; hSCObject
			FF D5              call    ebp ; CloseServiceHandle
			68 B8 0B 00 00     push    0BB8h           ; dwMilliseconds
			FF 15 38 70 40 00  call    ds:Sleep
			6A 00              push    0               ; fCreateHighestLevel
			68 60 A9 40 00     push    offset PathName ; lpPathName
			E8 43 FE FF FF     call    RecursivelyCreateDirectories
			83 C4 08           add     esp, 8
			68 60 A9 40 00     push    offset PathName ; lpFileName
			FF 15 3C 70 40 00  call    ds:DeleteFileA
		*/
		
		$a = {
				56 
				FF D5 
				68 B8 0B 00 00 
				FF 15 [4] 
				6A 00 
				68 [4]
				E8 [4]
				83 C4 08 
				68 [4]
				FF 15 
			}
		
		$ = "wauserv.dll"
		$ = "Rpcss"
	
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-10
	Identifier: Dubnium
*/

/* Rule Set ----------------------------------------------------------------- */

rule Dubnium_Sample_1 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
	strings:
		$key1 = "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194" fullword ascii
		$key2 = "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Dubnium_Sample_2 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
	strings:
		$x1 = ":*:::D:\\:c:~:" fullword ascii
		$s2 = "SPMUVR" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Dubnium_Sample_3 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "caefcdf2b4e5a928cdf9360b70960337f751ec4a5ab8c0b75851fc9a1ab507a8"
		hash2 = "e0362d319a8d0e13eda782a0d8da960dd96043e6cc3500faeae521d1747576e5"
		hash3 = "a77d1c452291a6f2f6ed89a4bac88dd03d38acde709b0061efd9f50e6d9f3827"
	strings:
		$x1 = "copy /y \"%s\" \"%s\" " fullword ascii
		$x2 = "del /f \"%s\" " fullword ascii
		$s1 = "del /f /ah \"%s\" " fullword ascii
		$s2 = "if exist \"%s\" goto Rept " fullword ascii
		$s3 = "\\*.*.lnk" fullword ascii
		$s4 = "Dropped" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 5 of them
}

rule Dubnium_Sample_5 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		super_rule = 1
		hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
		hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
		hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
		hash4 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		hash5 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
		hash6 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
		hash7 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash8 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash9 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"
	strings:
		$s1 = "$innn[i$[i$^i[e[mdi[m$jf1Wehn[^Whl[^iin_hf$11mahZijnjbi[^[W[f1n$dej$[hn]1[W1ni1l[ic1j[mZjchl$$^he[[j[a[1_iWc[e[" fullword ascii
		$s2 = "h$YWdh[$ij7^e$n[[_[h[i[[[\\][1$1[[j1W1[1cjm1[$[k1ZW_$$ncn[[Inbnnc[I9enanid[fZCX" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

rule Dubnium_Sample_6 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		super_rule = 1
		hash1 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		hash2 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
		hash3 = "839baf85de657b6d6503b6f94054efa8841f667987a9c805eab94a85a859e1ba"
	strings:
		$s1 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&()`~-_=+[{]{;',." fullword ascii
		$s2 = "e_$0[bW\\RZY\\jb\\ZY[nimiRc[jRZ]" fullword ascii
		$s3 = "f_RIdJ0W9RFb[$Fbc9[k_?Wn" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}

rule Dubnium_Sample_7 {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		super_rule = 1
		hash1 = "16f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
		hash2 = "1feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
		hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
		hash4 = "5246899b8c74a681e385cbc1dd556f9c73cf55f2a0074c389b3bf823bfc6ce4b"
		hash5 = "5f07b074414513b73e202d7f77ec4bcf048f13dd735c9be3afcf25be818dc8e0"
		hash6 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash7 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash8 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"
	strings:
		$s1 = "hWI[$lZ![nJ_[[lk[8Ihlo8ZiIl[[[$Ynk[f_8[88WWWJW[YWnl$$Z[ilf!$IZ$!W>Wl![W!k!$l!WoW8$nj8![8n_I^$[>_n[ZY[[Xhn_c!nnfK[!Z" fullword ascii
		$s2 = "[i_^])[$n!]Wj^,h[,!WZmk^o$dZ[h[e!&W!l[$nd[d&)^Z\\^[[iWh][[[jPYO[g$$e&n\\,Wfg$[<g$[[ninn:j!!)Wk[nj[[o!!Y" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

rule Dubnium_Sample_SSHOpenSSL {
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		author = "Florian Roth"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "6f0b05d5e8546ab1504b07b0eaa0e8de14bca7c1555fd114c4c1c51d5a4c06b"
		hash2 = "feaad03f6c0b57f5f5b02aef668e26001e5a7787bb51966d50c8fcf344fb4e8"
		hash3 = "41ecd81bc7df4b47d713e812f2b7b38d3ac4b9dcdc13dd5ca61763a4bf300dcf"
		hash4 = "bd780f4d56214c78045454d31d83ae18ed209cc138e75d138e72976a7ef9803f"
		hash5 = "a25715108d2859595959879ff50085bc85969e9473ecc3d26dda24c4a17822c9"
		hash6 = "e0918072d427d12b43f436bf0797a361996ae436047d4ef8277f11caf2dd481b"
	strings:
		$s1 = "sshkeypairgen.exe" fullword wide
		$s2 = "OpenSSL: FATAL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 9000KB and all of them
}

/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="3ebf96b8b7ae0142c0d88bbdb9057197"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="5f4dcc3b5aa765d61d8327deb882cf99"
    $a4="9b93a196ac81d5582c7822fbf85b1b25"
    $a5="28205a1a2d93927fb5837d3a48829ef7"
    $a6="63a9f0ea7bb98050796b649e85481845"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="63a9f0ea7bb98050796b649e85481845"
    $a9="e27c247993eda966a30472b956aeffbf"
    $a10="c6a33911cc53df9bdb84aac8d86a0565"
    $a11="78d1e470dd2a43d9ff4eecd93bf9ba8d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="c74e38b2ea1b16b194865e840492bd7d67e8f252"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a4="d6f772f88778b22626d2b862a14a46148185778e"
    $a5="957b77b65a6526c830b17799cf87e639ef6c230f"
    $a6="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a9="d8ecf50d08b30f68eccafc3532bb9c9fcc5bdd75"
    $a10="8a77613b475e46064321fd7da18d126ee35e5066"
    $a11="9607639aef7e6cbd2a2757d9efe3306228ce81c1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="47f1e5c383194e5b9ab338e45f2c1c226ea49345f7c30b38841df4b9c556877314c7b532b14fabfa455e93061b1e37c8"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a4="8c438a0b26136df1d7894c56ba13524949c91aa81a5ace7416743392b5ff09ce0f736ff2bb9489f6dbc4d7d834038edd"
    $a5="1b52b016bf98b7e67fe0cd4cebfb2d087036ac185c0611af3fcedc59ab80d3f7fc4aba658f900b7ddba64e81e40fa7bb"
    $a6="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a9="7714158131b38105ba1a1dd1e427a56d57119056fc672b1d28e79e452ad4456a037b69f8fc8ea09b8f84b0361c403ac1"
    $a10="18cbfb902f16c781142cbe9c134e2b1ea7eded6c1a881678b6f1c5254b719540665f8ec465fd2f1995bafe794ba7d801"
    $a11="54dc0bc33ce667b5fa8052d34f340e4e843909703025cdfa71b69be58dd495d519314e825bce845c521219b37a396249"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="f21d92d4e12af760eaccb4168521a8649d5b76415f4b4097b4c4d30a"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a4="101111087b7707e181db649390773370f8b4742746f0e88793b8c27e"
    $a5="026538e5757f5fff4745bd506644010d39776027c1d3b302d4959dd3"
    $a6="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a9="379a46e85d7be930571ab4ef689f10b258ea99318a014e62274479d9"
    $a10="a16b0181d196e34fc0b662184adcba6e440801e1c3cb7a47cabc162c"
    $a11="d35e70814fe2e2013fca23dd9b7cb67985f65f4aadd7c7d5d0f4caf9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="2de92e49aa6c2d146440bf6162178433a07120e57f1c1fc7f12821e1d21044f15e1b050a491c1860662092d1b3aa989ded8581089c4a9ed9d1fa7d85c45ce11e"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a4="dff2bc14e152889058764e1d58a0d7cd41509feb70d986f9757eff8947a0321a7710d97019a79241f0e5caf9f718e12d4950b3beb852f0ab78954a0cc9915d93"
    $a5="d633fb1d21b919712985b307728e1cae1220c75db85bcf8c11e50ddcd946b87618232618e01d22f258ea0b1febc06d75d9a76760736ad63494f18f6a0cb68882"
    $a6="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a9="d716064bc0e1935ee1b8e66c9991d163307ae05c6a2c8518e750ee3d0c7e23f297ffa7e92f84a9fe718cf4215089c180920868569c11701da34803103737a0ea"
    $a10="47dac71b14bc4892f418563c2c44efd0d20df0588e2b6b65ed611dcda0f99e64b1373b57528ce2ef9a8d9f63d58e88c5ded5ad88032afec577789ce01dc6c43e"
    $a11="dd13455b8c4fe096351cb50144ecaa8cd132a70f120e5800b2bfa4796a73215e7ecbaea693a993300d3d7b0d885a25329eb4da9c4bf525e1dec415dada427fb0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="ee5c6e2db57421c343ad811d5b9d2fc7a619d09791f547a79cb76e3a2094e4d9"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a4="862f957bff971a511b2a804c86639d819d6c5a78cc82800440a14316ce692fd0"
    $a5="a8d304e8471af555b0079bacfb70810e4783b5454a6f836ba3c2f23452f3308f"
    $a6="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a9="04e43902471c9ab7935a25360a0c2dc5915d0bcb601f5bcaf1a9fcc97f3bacbc"
    $a10="e41a2b6503b00fb488a6cc399cb6815efc768916b9acf7819a2375cc56540a50"
    $a11="7ea9dc2a17d2b8888d6989855d3d13a391ef17cef3551f67dd01724189064d50"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="0daa60dce56556502b2a05ce446a635ccbd645851b4625bf9f32da03a945c73624b56c9346de2b718554c502cf7f96544044913c1961839f0d2e9e9ec67be736"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a4="fe03ff34c8b135660afc2d240ba444ee1305182be6e0da51ff1343408b646da7401ea8c6ea4b87ffd04ae03c687eed6f6d078b35c9272c77a50c383ac8a8931f"
    $a5="fa3a147cd2a2861057edc69183e7171e0dfbbd76ecda9875c201c546c378e9ecf75d0cb13b22536540061ce0093cc5dbb08720e3f64ecc5991bdd2a624afa072"
    $a6="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a9="a00776d99560ad680b1d3a12a848b54d0238559ae1264af9a8aceba445af6a3593c457f684ab23f9ef18a09bfd6f33b894f51775e169a6832e816b121e5cb34f"
    $a10="d5c6d67da69608b42fdac3fb407f209c71efa344d77e446f12e8b73bae873e8837e8eb03b30b29f4ac27a99ec080be30cf8e5da6423942a22f51dea3f0f196b4"
    $a11="11ece2058bc1d9b592b585b11d018f73067086e1e8b4d53c4cb6871bb9ba5c5673bca32a323b8d09819a1b9c35014610a0c71ac25f2e4f72c5e0db9fe2973fae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="67f73e310bd2a811228028ef141d33aa80d1d438c65b8ab8e9859087be2e9449"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a4="708109fb58c3df709b898c9b6dbe620816bc4f91f1c089b7e0acabd2acbcc4d7"
    $a5="34c9eda7c76c43f0dbe80aa71a87c709173327ab81f6a6159d4eabee624854f7"
    $a6="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a9="85f788510c30939dd22bb14176b615d585b0d500e3e2bc6b2b4a581d0a821420"
    $a10="15435fbf1b82e0ad687264f141a79e10ecc498c6b2e30d1f489e0561ba15b879"
    $a11="e74964bf0966ab850c05e184d2b4b2c6c23f75ea831b24a2956ef66c4b64e660"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="bbcaa05993e82c42128a3400cf415375a59b43a33d78373090aa8f80"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a4="e588e772284639c0b704b3a3579c75048f588e26d7391642e58db5a4"
    $a5="aa1f92728d09b520296e2969685797efa62ce7a9e03283b641c78ffd"
    $a6="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a9="def96bd6cde0d3bfe76786dfd9a2568d168335ef8223c8c74833c98e"
    $a10="09620fd7325bcd5af39bdbfbd56a57991823aa514e84f19eb5c23c12"
    $a11="3d0f2bee930d492e3c2ee402175031cd4539f554522c424dc86d31f9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="821c5b8df143a9e3b19c314c1d84bb91235c7504038ca20d215672ca5b9a8217"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a4="f325e8a45689e7c93a6a5540c3ab2ce6feaf763a3166b7dd3fd25cf7c6c6c92c"
    $a5="7b01874fbdacafa045b51b9cd998c4840c3c7746b9f5343723dcfde1a0ad979c"
    $a6="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a9="e787eeef9f29be13838111ba1c1267d6ed9f64d2ee862b863d16c32adff482bf"
    $a10="f88ca7c8ebc412c940cc28cdb8ff244ef3b94421ef955241d1f6f54fa6557814"
    $a11="ff69d6c044543a4c14088b32b7acf489501324dcd38342347f855cff8fd6e9d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="07cbdddda0636f8ac1df259e3f8cbb68c1887dc59251c8e904b572c5badddbf6ab44e1c076d30eab657a2538df652e18"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a4="05278801e977cd312fc2530cb4a77a89a1b5f21568cb762f6706f80fc9cbbb5ec7c37375a4cd667695ae38e8988cfed6"
    $a5="55c64fec0ec5ebfa89674e5b259187849d53f1103effd7abeff4d8e34c0444164333aa9c011f0163e25bf3c07799e213"
    $a6="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a9="c3166cfbcdbcef03cbce88986f46fa957a133073ef15d5d73c2857eea941a3fe7321515e03e1293e1fa8f514d54ff4cb"
    $a10="39bc1f48c0ab323564360bf47522ae8bf6482281525d5ef5e45081cb9c69cc506698a7a795032d7aa17e7554b62080db"
    $a11="0242332157f9fa630c5fd3936cc897a0d6be23b7708738605be81a4895eac87a5fed7dfbaff90db486bcb229cde645e4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="de5f3dfc640624f37c44bb2a9fe695abce8f127b415710e3b9ed0589c4146382ef5e365b564f54c7dca427680b6bf4105b450fd47f6c04b1590062ab8d57a034"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a4="91d9afe9c786478c48ae16d1e70d70498defc79d2a28979635d077095c4e2658d765d9b459eaaddfcb81d9c7eaca42314b9c04b34bb0118e50233a901d7504a8"
    $a5="c5385c68a309241ad34389489227e61cb2ad7191aa392e08d9582c540514263f268491def99f1f479c12b79c2b97d13bcfbcbd59f2937636177849b5d0314f36"
    $a6="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a9="600700053a68627643a47c88b59df33ad817ef4c2173af8d46893e5a91adb50775925f1bcbd7579942cbb04713a7157c8ecde6132db5e07f77a4b4fff733ae62"
    $a10="de919babf8aaa4b61eee7bb4d13c2b317977cc7552a2520041661b9babcd6dc542b8145a7b8efa5532c751887b99016fa3ab29acff4b7d99a3ba99d96eb22804"
    $a11="9c15048bc812d9f22ecbad8eaf0677b43cb75d1865b50737e84879ec1adc1c819e728b92d11b2321243c1aa6ccb143ec241e476e4e2376cc888bbfe963e928a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_wyse
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for wyse. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="RmlyZXBvcnQ="
    $a2="===="
    $a3="cGFzc3dvcmQ="
    $a4="cmFwcG9ydA=="
    $a5="ckBwOHAwcis="
    $a6="cm9vdA=="
    $a7="===="
    $a8="cm9vdA=="
    $a9="d3lzZQ=="
    $a10="Vk5D"
    $a11="d2ludGVybQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}


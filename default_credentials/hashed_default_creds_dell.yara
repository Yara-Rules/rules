/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="e3afed0047b08059d0fada10f400c1e5"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a5="d3a9194c76fbc114d0ae11515ba4f325"
    $a6="21232f297a57a5a743894a0e4a801fc3"
    $a7="5f4dcc3b5aa765d61d8327deb882cf99"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="997e07559f7b0563ca07c0a60d675d09"
    $a10="d41d8cd98f00b204e9800998ecf8427e"
    $a11="21232f297a57a5a743894a0e4a801fc3"
    $a12="d41d8cd98f00b204e9800998ecf8427e"
    $a13="ab2724d10b490217916b1bcc56aef48f"
    $a14="d41d8cd98f00b204e9800998ecf8427e"
    $a15="3ebf96b8b7ae0142c0d88bbdb9057197"
    $a16="d41d8cd98f00b204e9800998ecf8427e"
    $a17="5e228892aa3ea80a488c985839302ac7"
    $a18="9b93a196ac81d5582c7822fbf85b1b25"
    $a19="28205a1a2d93927fb5837d3a48829ef7"
    $a20="63a9f0ea7bb98050796b649e85481845"
    $a21="e6e66b8981c1030d5650da159e79539a"
    $a22="63a9f0ea7bb98050796b649e85481845"
    $a23="e27c247993eda966a30472b956aeffbf"
    $a24="c6a33911cc53df9bdb84aac8d86a0565"
    $a25="78d1e470dd2a43d9ff4eecd93bf9ba8d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha1_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a5="dc004fc311edc14e3686134a1c7655842059d856"
    $a6="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a7="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="397c51d7585aa5becba2946f6786e66779131635"
    $a10="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a11="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a12="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a13="e73a719286c573a494723e36cea92fa0e22ef333"
    $a14="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a15="c74e38b2ea1b16b194865e840492bd7d67e8f252"
    $a16="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a17="e68eb4be260c1f1a56cc19f08916ecdf1771e6e7"
    $a18="d6f772f88778b22626d2b862a14a46148185778e"
    $a19="957b77b65a6526c830b17799cf87e639ef6c230f"
    $a20="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a21="cb654ac8f36f840016f043aa3e4e06796529704d"
    $a22="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a23="d8ecf50d08b30f68eccafc3532bb9c9fcc5bdd75"
    $a24="8a77613b475e46064321fd7da18d126ee35e5066"
    $a25="9607639aef7e6cbd2a2757d9efe3306228ce81c1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha384_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a5="3ffe983f04b0d7364baf4bf7633a38e4c0dade270aab3f883383156afb6e45104b56ce8c7228efa96ce04a3ab2ea675f"
    $a6="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a7="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="9eaddd0fcb409d5fab8c469211eb1f1cadc34d846e9049a1732934263e7e93c20b410a76fc8a408f130c43128c868c0d"
    $a10="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a11="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a12="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a13="9b325ac7426680840e905c5bca9f936c711aa26801acc1f2dd68cbbc8a9c1bcd4c9e47e2cefc4f3301459256e8ff27db"
    $a14="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a15="47f1e5c383194e5b9ab338e45f2c1c226ea49345f7c30b38841df4b9c556877314c7b532b14fabfa455e93061b1e37c8"
    $a16="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a17="1afef38675489f9edbb1c919795d29ecd09863b523cb28172afd4222b38817c06dfca0b157892dd7499a19cbd937284d"
    $a18="8c438a0b26136df1d7894c56ba13524949c91aa81a5ace7416743392b5ff09ce0f736ff2bb9489f6dbc4d7d834038edd"
    $a19="1b52b016bf98b7e67fe0cd4cebfb2d087036ac185c0611af3fcedc59ab80d3f7fc4aba658f900b7ddba64e81e40fa7bb"
    $a20="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a21="e71efaf23c5c76bd9286b89306a8226d8f77fd7a17299fe56f2a36ce2cd505b6eb314dd95a5d63ffe0b7cdbb7e86895c"
    $a22="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a23="7714158131b38105ba1a1dd1e427a56d57119056fc672b1d28e79e452ad4456a037b69f8fc8ea09b8f84b0361c403ac1"
    $a24="18cbfb902f16c781142cbe9c134e2b1ea7eded6c1a881678b6f1c5254b719540665f8ec465fd2f1995bafe794ba7d801"
    $a25="54dc0bc33ce667b5fa8052d34f340e4e843909703025cdfa71b69be58dd495d519314e825bce845c521219b37a396249"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha224_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a5="a866c5323df6eedc8e5e8d703e43f9323c83781941000e3ae52d2bad"
    $a6="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a7="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="c287a4e7cf1b57f2fde65a51532c322f09c806e48715d3f1bcd56e79"
    $a10="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a13="a9998100c9e96f5248c13d5829672007add4e8605477a2e9a90e4d5d"
    $a14="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a15="f21d92d4e12af760eaccb4168521a8649d5b76415f4b4097b4c4d30a"
    $a16="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a17="ef602fafa35837a5970255b7463b56e7897e2ae0c87697c5536faffc"
    $a18="101111087b7707e181db649390773370f8b4742746f0e88793b8c27e"
    $a19="026538e5757f5fff4745bd506644010d39776027c1d3b302d4959dd3"
    $a20="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a21="f06a391a1f76cbfa4cdccf29b53c4208882dd2a7365f2589f2d8970b"
    $a22="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a23="379a46e85d7be930571ab4ef689f10b258ea99318a014e62274479d9"
    $a24="a16b0181d196e34fc0b662184adcba6e440801e1c3cb7a47cabc162c"
    $a25="d35e70814fe2e2013fca23dd9b7cb67985f65f4aadd7c7d5d0f4caf9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha512_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a5="47f4b1fd9ef0b44453e263c33807e9d8376f99f80b95f9e6a997f02a62dcefd8a8cda9f4b40af5011b59a92e0f5df9e9e18a15c943176fe6a48c9a34f5c08b02"
    $a6="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a7="b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="d93fecaf6cab277508403d89ce71594e3de5bfe1e3616aa14486f9cbb90f230d41fcafd69309cbdb8ff1f913b33351b3aa58dad1792fdf7c96b9c43c16e0c4de"
    $a10="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a12="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a13="5693037bfa554df2e04a67f2ff407c8c8a7b1e76084f16c0ec745d34aa677b1c604c7b2fa27ac4ea6738f13f8ae44d156333cce33fea52bb2a1eece41705bbad"
    $a14="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a15="2de92e49aa6c2d146440bf6162178433a07120e57f1c1fc7f12821e1d21044f15e1b050a491c1860662092d1b3aa989ded8581089c4a9ed9d1fa7d85c45ce11e"
    $a16="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a17="a71b18d99957aaec67c3d77be13204108f9810fd1452f01857c871492063c39f0b0e566bb7513bc9d081276bdb9953cbdcb9a634483448a7cc46bf437fb71418"
    $a18="dff2bc14e152889058764e1d58a0d7cd41509feb70d986f9757eff8947a0321a7710d97019a79241f0e5caf9f718e12d4950b3beb852f0ab78954a0cc9915d93"
    $a19="d633fb1d21b919712985b307728e1cae1220c75db85bcf8c11e50ddcd946b87618232618e01d22f258ea0b1febc06d75d9a76760736ad63494f18f6a0cb68882"
    $a20="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a21="a71e2cf7a3235dbea0d1f9a7a11518c674c299ff7cee2b4e8d9fbf531e3d1c5dd9f9ec9162113ecadfa92175a64c523fdbb27f38def2a2b591adb07497fb1fd1"
    $a22="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a23="d716064bc0e1935ee1b8e66c9991d163307ae05c6a2c8518e750ee3d0c7e23f297ffa7e92f84a9fe718cf4215089c180920868569c11701da34803103737a0ea"
    $a24="47dac71b14bc4892f418563c2c44efd0d20df0588e2b6b65ed611dcda0f99e64b1373b57528ce2ef9a8d9f63d58e88c5ded5ad88032afec577789ce01dc6c43e"
    $a25="dd13455b8c4fe096351cb50144ecaa8cd132a70f120e5800b2bfa4796a73215e7ecbaea693a993300d3d7b0d885a25329eb4da9c4bf525e1dec415dada427fb0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha256_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a5="d6cbfe3e2b49ab03980c1d095e95a916e41b152ddbabbd0dbe3bba37a63ce878"
    $a6="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a7="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="1e4d0d584d3b380fb6474fed7b43a878efb9276871d5a4dbc962ec469ffed385"
    $a10="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a13="e9c5e07631ef4658d1b0613f0bf1e906f2d3471ed62264bf41d22151b592a618"
    $a14="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a15="ee5c6e2db57421c343ad811d5b9d2fc7a619d09791f547a79cb76e3a2094e4d9"
    $a16="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a17="13f7284eab569a9be2eed5cd3de5681d41a25fb28d7b0f6188341d1f1a1768bb"
    $a18="862f957bff971a511b2a804c86639d819d6c5a78cc82800440a14316ce692fd0"
    $a19="a8d304e8471af555b0079bacfb70810e4783b5454a6f836ba3c2f23452f3308f"
    $a20="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a21="a7fe9dcbcafa8559ea3617a3a21af7b8aa06c2badf7322c67c5ee6b6f880cdb1"
    $a22="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a23="04e43902471c9ab7935a25360a0c2dc5915d0bcb601f5bcaf1a9fcc97f3bacbc"
    $a24="e41a2b6503b00fb488a6cc399cb6815efc768916b9acf7819a2375cc56540a50"
    $a25="7ea9dc2a17d2b8888d6989855d3d13a391ef17cef3551f67dd01724189064d50"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2b_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a5="ee9571c711b94967896fcb640fa19376c669d859f4cffd1b2bc5660da8e020b5a6e01031e4044986bda07dea29593aae5013ccdbe47a922149a23dde9fff4fbe"
    $a6="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a7="7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="21b02d666623523dc6e6adf7937012ca0adb2a27418d48d4f8f0e1dc6e135fd71dfa051bb441d9e890b54c685ec64eadac34d724634a56dc1b097d16b19e2c13"
    $a10="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a11="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a12="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a13="f06368b4b0cd7bb0aec31fc1ea9b351a1272a640f647d569bbff69ebda3bc9e992ccc7de594dff75430a8252088f94f551f237051b1b8a40a0fbfa0c35957d74"
    $a14="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a15="0daa60dce56556502b2a05ce446a635ccbd645851b4625bf9f32da03a945c73624b56c9346de2b718554c502cf7f96544044913c1961839f0d2e9e9ec67be736"
    $a16="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a17="230ef7f8883f6cc4320bc39912d14a23b2dae8fccdba7d161b84c83960d03696687793c372b65cd54330a71d068b67261dfb7725d391c11169feb025af06bb4b"
    $a18="fe03ff34c8b135660afc2d240ba444ee1305182be6e0da51ff1343408b646da7401ea8c6ea4b87ffd04ae03c687eed6f6d078b35c9272c77a50c383ac8a8931f"
    $a19="fa3a147cd2a2861057edc69183e7171e0dfbbd76ecda9875c201c546c378e9ecf75d0cb13b22536540061ce0093cc5dbb08720e3f64ecc5991bdd2a624afa072"
    $a20="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a21="9f171b86b7587c25d2f8f3a5dbd7f8f49061735a938caf8bc632509940653ba4d38ebbd7761f02ef25fd2cbe32c1cc0fefc9a10fcc2150b5f05c96c704c5e8e5"
    $a22="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a23="a00776d99560ad680b1d3a12a848b54d0238559ae1264af9a8aceba445af6a3593c457f684ab23f9ef18a09bfd6f33b894f51775e169a6832e816b121e5cb34f"
    $a24="d5c6d67da69608b42fdac3fb407f209c71efa344d77e446f12e8b73bae873e8837e8eb03b30b29f4ac27a99ec080be30cf8e5da6423942a22f51dea3f0f196b4"
    $a25="11ece2058bc1d9b592b585b11d018f73067086e1e8b4d53c4cb6871bb9ba5c5673bca32a323b8d09819a1b9c35014610a0c71ac25f2e4f72c5e0db9fe2973fae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule blake2s_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a5="5230474dc1d57c362608192d4d5419f970eaae768488f0eb31ff516c1a58fa2f"
    $a6="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a7="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="693f9b3dc659c5e5ae439dedbc29c32c6399daefdf858d6032474fcfd5b82a23"
    $a10="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a11="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a12="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a13="ba418891e0936cd1a6173972f2446c2ca41fc9efe1c8e0088cdb1d89ea9cbfd4"
    $a14="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a15="67f73e310bd2a811228028ef141d33aa80d1d438c65b8ab8e9859087be2e9449"
    $a16="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a17="b36b90c6de133e40cb51c97a8c188d3a237d359fba4011b82a43305b4ce09808"
    $a18="708109fb58c3df709b898c9b6dbe620816bc4f91f1c089b7e0acabd2acbcc4d7"
    $a19="34c9eda7c76c43f0dbe80aa71a87c709173327ab81f6a6159d4eabee624854f7"
    $a20="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a21="345083deb54e99d43195872fa21882f4f0fa3453d3d031198f1b324a9449aa58"
    $a22="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a23="85f788510c30939dd22bb14176b615d585b0d500e3e2bc6b2b4a581d0a821420"
    $a24="15435fbf1b82e0ad687264f141a79e10ecc498c6b2e30d1f489e0561ba15b879"
    $a25="e74964bf0966ab850c05e184d2b4b2c6c23f75ea831b24a2956ef66c4b64e660"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_224_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a5="40377f8ab627ae88a37da8ded5993ff24129bf3e824c803a57c04f14"
    $a6="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a7="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="4e7978fbaa3571f2455bcdb22958771ac07cf0e44a42c38b1dcbd5ff"
    $a10="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a11="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a12="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a13="2c546a70ad1a86ba76619891d633cb13c3dac6b61fae9841fbd6202d"
    $a14="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a15="bbcaa05993e82c42128a3400cf415375a59b43a33d78373090aa8f80"
    $a16="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a17="573b7ee2d9a9bdc0f85e1311b2e341fd4f62ae4f830ed0be09bf5b85"
    $a18="e588e772284639c0b704b3a3579c75048f588e26d7391642e58db5a4"
    $a19="aa1f92728d09b520296e2969685797efa62ce7a9e03283b641c78ffd"
    $a20="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a21="4c98463652e78dc9aed2411abb079c3ccaf5be3ca000e3cd4683e2de"
    $a22="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a23="def96bd6cde0d3bfe76786dfd9a2568d168335ef8223c8c74833c98e"
    $a24="09620fd7325bcd5af39bdbfbd56a57991823aa514e84f19eb5c23c12"
    $a25="3d0f2bee930d492e3c2ee402175031cd4539f554522c424dc86d31f9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_256_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a5="f278c670e03e528f8992c36d3df37bc9ff50e7c182f3b9550acc374ebbc3b6fc"
    $a6="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a7="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="3e87ef224378529dce0e3ffcf5ac259c3cf313a159934fe71e90086a39d20a54"
    $a10="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a13="32b6a2b36b299559b455db42ddba4274ddf2f5e96d9fb6f57086bf508f9de981"
    $a14="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a15="821c5b8df143a9e3b19c314c1d84bb91235c7504038ca20d215672ca5b9a8217"
    $a16="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a17="e47b4a697d165520e31e1a4022df506e792dae7b7ea2c8e7502ae7de80f3d50d"
    $a18="f325e8a45689e7c93a6a5540c3ab2ce6feaf763a3166b7dd3fd25cf7c6c6c92c"
    $a19="7b01874fbdacafa045b51b9cd998c4840c3c7746b9f5343723dcfde1a0ad979c"
    $a20="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a21="bbe30e1fb5a433233667618f4f1fbceb8f77b14ab2823efe3ab23c356662f013"
    $a22="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a23="e787eeef9f29be13838111ba1c1267d6ed9f64d2ee862b863d16c32adff482bf"
    $a24="f88ca7c8ebc412c940cc28cdb8ff244ef3b94421ef955241d1f6f54fa6557814"
    $a25="ff69d6c044543a4c14088b32b7acf489501324dcd38342347f855cff8fd6e9d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_384_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a5="dcee086896e14c296ff7d0d13939e8eb5571a9343f19ab1bd9280d81e4301e8656b61b0d14cf71422fdf6efc3e74d100"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="e76269d650d2e3a89d7b09144516c8254c89a9d6b4c05a07eab1512244534b0d33e2b6440e057ffb0d28678f52e2d52e"
    $a10="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a11="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a12="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a13="72bf87f445356b341d5a38ec3840e0252402c6237d5ee344261144ed52ca255995b79d7d6611315235845f2b76c211fb"
    $a14="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a15="07cbdddda0636f8ac1df259e3f8cbb68c1887dc59251c8e904b572c5badddbf6ab44e1c076d30eab657a2538df652e18"
    $a16="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a17="030d78f4ba883abb0f685f3558b3fffc26597da27d3fcf14d828ab731dc0194ec187e2a31d49e5e8f079a5fd80d89bf5"
    $a18="05278801e977cd312fc2530cb4a77a89a1b5f21568cb762f6706f80fc9cbbb5ec7c37375a4cd667695ae38e8988cfed6"
    $a19="55c64fec0ec5ebfa89674e5b259187849d53f1103effd7abeff4d8e34c0444164333aa9c011f0163e25bf3c07799e213"
    $a20="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a21="b7a887909df67a32ad28776d54fd260459f83e6dabb13471bd54c426a1b2b8e1f980383caf90083ab9a9581b5d662e72"
    $a22="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a23="c3166cfbcdbcef03cbce88986f46fa957a133073ef15d5d73c2857eea941a3fe7321515e03e1293e1fa8f514d54ff4cb"
    $a24="39bc1f48c0ab323564360bf47522ae8bf6482281525d5ef5e45081cb9c69cc506698a7a795032d7aa17e7554b62080db"
    $a25="0242332157f9fa630c5fd3936cc897a0d6be23b7708738605be81a4895eac87a5fed7dfbaff90db486bcb229cde645e4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule sha3_512_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a5="913bd2039c6ec7d97bbd358a16125367b4c8cc534fcdb6369a5419aa309d642ad43c2e7f5ecc7f7ae4ed3967c96c85bdf3663929d7d0b605d4a1c03b538fbe94"
    $a6="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a7="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="9477a3679fcb6ec19341f77179173db3be6e25c71b6e65cbeacdd89cfcf0764296dd514a8d1996bf43087823758b05ea2e1755798fc6ce7c268118c8c070a6ee"
    $a10="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a13="18a3a6e3877ad6b19c3a96b7ebb507326c18bb3251ce532324a2208a26fe72189dea7098a6bee309075de23c4fdd3c45cbd7412346a0cf524a109283da69c03f"
    $a14="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a15="de5f3dfc640624f37c44bb2a9fe695abce8f127b415710e3b9ed0589c4146382ef5e365b564f54c7dca427680b6bf4105b450fd47f6c04b1590062ab8d57a034"
    $a16="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a17="f987a7d9ba6b8766d76fbfd1855e931f7c1a9842f47091ee19de39b897dcf3a32a2b6aacf07dbe31b0206d9f5161e101f9917e687dcecadf94bd4d10c200e3c9"
    $a18="91d9afe9c786478c48ae16d1e70d70498defc79d2a28979635d077095c4e2658d765d9b459eaaddfcb81d9c7eaca42314b9c04b34bb0118e50233a901d7504a8"
    $a19="c5385c68a309241ad34389489227e61cb2ad7191aa392e08d9582c540514263f268491def99f1f479c12b79c2b97d13bcfbcbd59f2937636177849b5d0314f36"
    $a20="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a21="b92956a3364685ee38de61c588f054b20921d26c2a23f13ca0732d42d0f50e382f6a69f12adb37a2313657b2557e1c96dd90003e4f046ab16e1882e4edc8a70e"
    $a22="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a23="600700053a68627643a47c88b59df33ad817ef4c2173af8d46893e5a91adb50775925f1bcbd7579942cbb04713a7157c8ecde6132db5e07f77a4b4fff733ae62"
    $a24="de919babf8aaa4b61eee7bb4d13c2b317977cc7552a2520041661b9babcd6dc542b8145a7b8efa5532c751887b99016fa3ab29acff4b7d99a3ba99d96eb22804"
    $a25="9c15048bc812d9f22ecbad8eaf0677b43cb75d1865b50737e84879ec1adc1c819e728b92d11b2321243c1aa6ccb143ec241e476e4e2376cc888bbfe963e928a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}

rule base64_hashed_default_creds_dell
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dell. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="QWRtaW4="
    $a3="===="
    $a4="QWRtaW5pc3RyYXRvcg=="
    $a5="c3RvcmFnZXNlcnZlcg=="
    $a6="YWRtaW4="
    $a7="cGFzc3dvcmQ="
    $a8="===="
    $a9="MVJSV1RUT09J"
    $a10="===="
    $a11="YWRtaW4="
    $a12="===="
    $a13="RGVsbA=="
    $a14="===="
    $a15="RmlyZXBvcnQ="
    $a16="===="
    $a17="bnowdTRiYmU="
    $a18="cmFwcG9ydA=="
    $a19="ckBwOHAwcis="
    $a20="cm9vdA=="
    $a21="Y2Fsdmlu"
    $a22="cm9vdA=="
    $a23="d3lzZQ=="
    $a24="Vk5D"
    $a25="d2ludGVybQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23) or ($a24 and $a25)
}


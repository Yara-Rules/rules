/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="9df3b01c60df20d13843841ff0d4482c"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="140cda41b885a815e412ff75ce018213"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="54b53072540eeeb8f8e9343e71f28176"
    $a10="d56b699830e77ba53855679cb1d252da"
    $a11="9df3b01c60df20d13843841ff0d4482c"
    $a12="48a365b4ce1e322a55ae9017f3daf0c0"
    $a13="7a95bf926a0333f57705aeac07a362a2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha1_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="0f12541afcce175fb34bb05a79c95b76e765488b"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="1759cbe79ef61c1ec9e4b0f3e5431a0b68e0e3d0"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="317f1e761f2faa8da781a4762b9dcc2c5cad209a"
    $a10="2736fab291f04e69b62d490c3c09361f5b82461a"
    $a11="0f12541afcce175fb34bb05a79c95b76e765488b"
    $a12="a159b7ae81ba3552af61e9731b20870515944538"
    $a13="bd564db5d5cc358eb0e3523d3e03041739f230d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha384_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="49e18e684812e9034a6c1eef90b337cbc9ee8de6383e57b79f4bc255393417ab33def30f0f3398c5489c00faab52a619"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="51cc8186a4089f28100514686a2f2ab64ff9bccb8f3bfc56b4f68760849ec392129ebe419fd4bce929dd6793a1bc49cd"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a10="b188d166dc05c1c824c16ff6739f42c4dc8313da98a037289784daea7710c3402c13c2a9442dcbe19d33467381bf7979"
    $a11="49e18e684812e9034a6c1eef90b337cbc9ee8de6383e57b79f4bc255393417ab33def30f0f3398c5489c00faab52a619"
    $a12="da9b3e0e3764965ea1ea652d0d504c40c14ffb05d26a1eadda70833bba54782b7e427a6c75003c8c8ecd96ffea88cdb8"
    $a13="78e42a356435093bf78bb56c3adf897e884f9b2c8bf0bc719ece297b505869959cfe9efb64108e4063414479b1fc597d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha224_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="24289a24be5d6ee8df8f3cedf9b538b4cb69fbaf8abca98797b328ac"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="f443aec0077a91b129c527dbf61131081fef6e8009a207b8aa89a5d6"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="fce0f71a2798bc7c8871be4e1be3407301e5264340664fc1800474ea"
    $a10="6583756055182f816b6c5dba70cabb3be2813c2a57f645ca2f7f79a9"
    $a11="24289a24be5d6ee8df8f3cedf9b538b4cb69fbaf8abca98797b328ac"
    $a12="02f382b76ca1ab7aa06ab03345c7712fd5b971fb0c0f2aef98bac9cd"
    $a13="7ba5f98ac94c57079d6452cfe6521165cc182a5d25927002a1ad7d99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha512_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="932778fa1dd9a15dac1f6d7690b29b70e9c205a8d2b4a437f007bf6df4fe3c5200520078f95184bd37ce6ed67f362a42b4263ed4c8ba6d777b0166f9af879897"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="8c514795fee1c59a3de6c1650af287dc533280be602c496d5be9faaa4d1cfdbd68299e32d5338b5a89ad10c927b3c3e02906ebcd4c21e8b228d618196b8a02bd"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
    $a10="107350f79b8400469b09b40b91710e81a4276c7744a20fdb11fbfb31b5936332ff682f57bb9b2318b970789f7f9d5ea26bc2ff0bc94f61935a4072ad8125fe4d"
    $a11="932778fa1dd9a15dac1f6d7690b29b70e9c205a8d2b4a437f007bf6df4fe3c5200520078f95184bd37ce6ed67f362a42b4263ed4c8ba6d777b0166f9af879897"
    $a12="f6235735d47e6ccc82cc743bb0f4578e2f21572003d61e62c719fd9345101031e6aeed4b2ba8b059916b3764dac90fbdb6a0a88fe5fa7d7f483013a63cc089e0"
    $a13="a19b7f9fe873c8f7932b0256dbc5836dfb64063dc84c824ae7a1fa652cff200cc8e437c95b46bdd21084521b3e6b15cad5ea5521db91fbd8a933a1460b1fc2ef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha256_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="9de19e8bc045e0f6ae1343c3b4cb09c35041a64a43566fe11d6827a05052891e"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a10="428821350e9691491f616b754cd8315fb86d797ab35d843479e732ef90665324"
    $a11="a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a"
    $a12="d577adc54e95f42f15de2e7c134669888b7d6fb74df97bd62cb4f5b73c281db4"
    $a13="2f9acb02faa121bb2a3621951f57b4c690655337edee2e5ac350be2b3be88ea8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2b_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="3668a081b0929274a97abf15209dab17ae30a35a7751a62e5515262524cb38b5216cff0ed604cf6a8f5f5b573aa0573735764a99a6028f22e0d2ea1eaaac810c"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="19cb361c51b32345361d11b4bbeb583e918afb6410895261cec609675d1d12ca0cc2e673073c223ba32a4372e54fa59f02e3f3b3092ff370e0c8f5ba8ba28d70"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="238c8c11f3d51d2304c78be26341850c0a118fbb4a581016ffc5a161b8cb7992715d0c90a69563cdf78be6bd954fe379c2dfaa3fe44117ce11e5bfc7b801edf4"
    $a10="02fa8d46fb2ac65ee42912604250a146af74c6b8cff1acd09bc5f460fb9850cad2674f76f982ed052c78d178196ed4c10256e2bc50e191dbb82f625cad071090"
    $a11="3668a081b0929274a97abf15209dab17ae30a35a7751a62e5515262524cb38b5216cff0ed604cf6a8f5f5b573aa0573735764a99a6028f22e0d2ea1eaaac810c"
    $a12="da668ac94129340a5db3fa3d91341413bbfd477fb277272bbee5122fc1ebef04a33a76c01ed027ea066b3b7f3819f487ba6dfeaaaff9a326b49c39519ec7f474"
    $a13="4a5da2ebd2552455f3ccde94a636d353fa7c4aa65a16c50bf27a0672412af4d5fcadfb936e371fb75e84d89ee436faff35cb6f9951268611733b60135457cf49"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule blake2s_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="13ed751afcecd936bcbe496a38545e63d2fb97f2ad8fc5b72f17d29784c34db5"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="4aa7e44aa9f5797c816d8418f88b09608661edbf6f397dad28a57b8c3f575481"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="541fbae7e33228c5ed638ce6d908ca541b57a43e73c05a9318ebc587849a9449"
    $a10="8a4c21160430a7a93bedcfd6876aa77a9269a4ab59aa6adb42692717f6a2bb80"
    $a11="13ed751afcecd936bcbe496a38545e63d2fb97f2ad8fc5b72f17d29784c34db5"
    $a12="0eac0ddb08d482a2cb9e297e499508a9e4f4b229229d43a6f2f78d129ebfb203"
    $a13="50306d5ff12c751f2aefc09e5b3df58b84a676fbebbb8fd17b84b6a445c6df5d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_224_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="a86118aed12772c63e1641003f22dadc2be7ee74d4cb33aeb0b3466d"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="71cf41077d94ac4978a9fa403337bf5d3e2673362c0916ce0e1bebfb"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="d301efe5d45841224c3f070d049ce96b96f15731080ad4f2d55f8b77"
    $a10="0509e9a858996f62da0f676687a1e2b209ed07819cd43f3021981b38"
    $a11="a86118aed12772c63e1641003f22dadc2be7ee74d4cb33aeb0b3466d"
    $a12="b3c613fcea10ca76dab2bae1ff0054b92d46aead56580e60898b6f82"
    $a13="44dce7e29c53baf26f62ba8fb762fa83014db48740a391cc97a16b7f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_256_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="1037f1f67277cd916301c10e5417b95c117abbd8daf2b794c30a90ee67898b53"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="151019c9fbc05ae68ef545d54fbc6b24332e60841b729e600d05cb37cedbbbcb"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
    $a10="a2ce5400c881d0469d3fda706ca5392fb9f351ff95a8a300e0fefd11b0bf1d32"
    $a11="1037f1f67277cd916301c10e5417b95c117abbd8daf2b794c30a90ee67898b53"
    $a12="78377bddcc5fb7199a28965a65772069ce9de533aa0b7ac7c63fde2e2cc95966"
    $a13="64e0033a157085ecc01bc7e53e9f6e032754676e57788f5b92bd147efbdc4a2f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_384_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="a1d1faa1bf43746f57d4e195f9c3c9b2de32e63ef8bb6a223c1c99e2576f0f62840c8b6f9a8d7e0f1afdb68150b529a2"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="6b499970ebf370d4dbc4e9a005c042dee003c19a9420a78944bcbf32653d257f80f7c56bad55b4c967dca68a1ea92be7"
    $a10="fc2b975d7d78d7a007b8577e807f66a26dfcf0a008a8678464c68d438dd6ee18a444ac5f594674f189183f2db8a15c95"
    $a11="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
    $a12="f5276408a10d9c8841ac9fc0a3002818b5d55ef8065c3dca312cf764e4ef7213ae21d3f35423123de91061a2ee8a0bb5"
    $a13="3acd17e3e97eaf1e83d90d5080eb21a6dc8480d001b9adce3a3aab542d485ef6805597e7cb61d046d1d084f03c414546"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule sha3_512_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="2ccefc4001cc12acc9512f44784c55dff5086894fd436dfcb30f64a2c5a55dbae984b86c749d29e10254c770f3b21ca6fc11d84ddd9077db29c6e6bcb4c48f24"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="b8828465c26635b5e585775ccbfcb68b1a0d5fd36ddc8cb5e55e1f1fb6c29a5b86e9de01659e40a525cf1094fa1a12fa4f3797d33d86f1dd16fd250d20c0e14f"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="097eb45ac7d97f03eebe74a62670a50bfc96e125833c3c43ef977745a9a656bfe0f16c9aaa187d04b2108e684022467086dc37e0e17e7e5983d3e8d10036af17"
    $a10="63d5cbf2a2135866c520f4b47404907891511d1f9a5d74e4326befa94120c92e805d6a7ce4e00c8fb0ce607d5623b19b5eec17e4b1ce20dbdb169cbb07827b9f"
    $a11="2ccefc4001cc12acc9512f44784c55dff5086894fd436dfcb30f64a2c5a55dbae984b86c749d29e10254c770f3b21ca6fc11d84ddd9077db29c6e6bcb4c48f24"
    $a12="100bcb6ac8e9f7bff18df1d6f6d0a41e7dfbddfdd55971bdd087c6c8039e02ae42ee60dcbc967ef03164de21fa0374152686c3c322f6e1bf56aeccc43fdfe3cd"
    $a13="e78d3d718b7681d5fddcdfeb18a55895828bbced7f64f8ad8c91043a3c7c0d2be0d9cdfabd969f89d156e2b19d2e6b7c4056a08385ff7ab43995503048bfe9b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}

rule base64_hashed_default_creds_lantronix
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lantronix. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="YWNjZXNz"
    $a2="===="
    $a3="YWRtaW4="
    $a4="===="
    $a5="===="
    $a6="===="
    $a7="bGFudHJvbml4"
    $a8="===="
    $a9="c3lzdGVt"
    $a10="bG9naW4="
    $a11="YWNjZXNz"
    $a12="c3lzYWRtaW4="
    $a13="UEFTUw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}


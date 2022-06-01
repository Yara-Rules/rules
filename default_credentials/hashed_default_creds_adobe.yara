/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="294de3557d9d00b3d2d8a1e6aab028cf"
    $a3="294de3557d9d00b3d2d8a1e6aab028cf"
    $a4="a56a94bf6b1c32f53d3f2524c42def08"
    $a5="bac7680036060d092d371672f311b50a"
    $a6="02bd92faa38aaa6cc0ea75e59937a1ef"
    $a7="02bd92faa38aaa6cc0ea75e59937a1ef"
    $a8="e66fde846efd7505dc42251c6ddc500d"
    $a9="a31405d272b94e5d12e9a52a665d3bfe"
    $a10="345bef9bffa11e0945df1e03cfa0fb37"
    $a11="d41d8cd98f00b204e9800998ecf8427e"
    $a12="345bef9bffa11e0945df1e03cfa0fb37"
    $a13="345bef9bffa11e0945df1e03cfa0fb37"
    $a14="0c5d82ccc18bdb8eadecf6b00acb34aa"
    $a15="0c5d82ccc18bdb8eadecf6b00acb34aa"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a3="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a4="5d672ecca683475ad849b35781f8e216b74088cb"
    $a5="07b94dce1c5fc71e0b62e5a34010e60fe9e50300"
    $a6="f64cd8e32f5ac7553c150bd05d6f2252bb73f68d"
    $a7="f64cd8e32f5ac7553c150bd05d6f2252bb73f68d"
    $a8="b10c316984dd14ef10108251e407840ead6de443"
    $a9="d35514736146439b7277437016cdb40d7fb65497"
    $a10="b05753f2d4fd4746e78a07788a0fc3ff48e8f35e"
    $a11="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a12="b05753f2d4fd4746e78a07788a0fc3ff48e8f35e"
    $a13="b05753f2d4fd4746e78a07788a0fc3ff48e8f35e"
    $a14="aa198c6806811aa31b6f07a581b851420af6a0e8"
    $a15="aa198c6806811aa31b6f07a581b851420af6a0e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a3="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a4="c00c73d64a94b012680430e9a1241bed72a2e396de9f10a2f6b90a16c3654b198c31899174a09b839782c3e47f96eb95"
    $a5="0f15c359d1f4e9588316f37364fdca3864a8bc93b245d669262673d7fdb385a9b668d3c2e08d849cb01717282d101358"
    $a6="fc295a302b9b9fe4b244696d373be482c16543f00e15c127296926ee41a5969e5b9696927698bbc1b44a3547e303e306"
    $a7="fc295a302b9b9fe4b244696d373be482c16543f00e15c127296926ee41a5969e5b9696927698bbc1b44a3547e303e306"
    $a8="8f898489836435195a82c599aedfdad6f159df00c370fbd477b508e5504cbc20073cdfae69213f91183d69a7b4edc391"
    $a9="1575fda7121294efb03433bb56065850cc2d37d6c90300df06ebe6734273e44119bafb13b07835ea87ef79ea9f288dcb"
    $a10="03fdbeadf6993c5788b0fe6fd8f7da64186f787512af18b9b1322751b8a5fca0f900204896ddcf5e33b45e515974f38a"
    $a11="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a12="03fdbeadf6993c5788b0fe6fd8f7da64186f787512af18b9b1322751b8a5fca0f900204896ddcf5e33b45e515974f38a"
    $a13="03fdbeadf6993c5788b0fe6fd8f7da64186f787512af18b9b1322751b8a5fca0f900204896ddcf5e33b45e515974f38a"
    $a14="6b88d88c864297536657c231b5904bf7528524267675c39565b8b8645948875cdc15f50cb2a19766e36db126d1b26cd1"
    $a15="6b88d88c864297536657c231b5904bf7528524267675c39565b8b8645948875cdc15f50cb2a19766e36db126d1b26cd1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a3="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a4="c1af3864fa7bf5c60173de1f31a5c6d975a612ed809434946e5a0e1f"
    $a5="7e700da0235e83c73d9869ab93d07399ce10609bd057f718aeb1de45"
    $a6="ba78a4b507e20f7d159503078770b0b1e3865e8ab6a9a85ab49a5486"
    $a7="ba78a4b507e20f7d159503078770b0b1e3865e8ab6a9a85ab49a5486"
    $a8="8d05e10cafca668b1c38ab4be6256a9803cdaaff40376b20b8a041e8"
    $a9="48b210d36dbf152408f768cf8bde8a706d012b76bcf88169891831ad"
    $a10="b5b56e63906bb925715eedca96f1470172785fbc7ac5814905c25c28"
    $a11="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a12="b5b56e63906bb925715eedca96f1470172785fbc7ac5814905c25c28"
    $a13="b5b56e63906bb925715eedca96f1470172785fbc7ac5814905c25c28"
    $a14="61dcf64c221209f4e886fe05706d8a1cdf7a25b6c17b4ca2d31b38f6"
    $a15="61dcf64c221209f4e886fe05706d8a1cdf7a25b6c17b4ca2d31b38f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a3="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a4="0925c768a48dcdcbc8b4b29802775443243ba31d59624a6796779ee7c85352313e425332fa236b1e6f53d3c905e3f672f2e7fe2eee8603284730999a57d78ada"
    $a5="54927c09868c20229c8575d1bf608bc204c693faa30a63908f9f570382f353bd721f6a5969a1d8a47557fd5947f16c2e9ca5fb8655e1f3c87cb51aa06f5f5a00"
    $a6="ff9afc6ec2604a9cd14bf322afa7e58fcd52198a5e3ec6b2ee12529ca1d0d4ed08729a9efdb1e66d45343b34ea2d448ad688fa7ea847f4fa020ea988cb6c496e"
    $a7="ff9afc6ec2604a9cd14bf322afa7e58fcd52198a5e3ec6b2ee12529ca1d0d4ed08729a9efdb1e66d45343b34ea2d448ad688fa7ea847f4fa020ea988cb6c496e"
    $a8="3aef3d311fd74b9e45edc2bb9d9f85b94056cd4dd2ef724541397a1ba4bb7a1693d2f6480d3c3e58e8fea841db6ac4ad2491809d245e8863900205bb99b884b5"
    $a9="fee256e1850ef33410630557356ea3efd56856e9045e59350dbceb6b5794041d50991093c07ad871e1124e6961f2198c178057cf391435051ac24eb8952bc401"
    $a10="d265752d58a2c98791a7affff1395b873f3bd4f4298e5cc3c40347f4d84158cbbad15b7b22deea56a56a22a2d9af2198a51ff42605757a9d30f39039b14d47c8"
    $a11="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a12="d265752d58a2c98791a7affff1395b873f3bd4f4298e5cc3c40347f4d84158cbbad15b7b22deea56a56a22a2d9af2198a51ff42605757a9d30f39039b14d47c8"
    $a13="d265752d58a2c98791a7affff1395b873f3bd4f4298e5cc3c40347f4d84158cbbad15b7b22deea56a56a22a2d9af2198a51ff42605757a9d30f39039b14d47c8"
    $a14="ebe0372ab9e479ffcf37de8d8807bb063aebe962918b8bb6114add1f1a3b1061339ef4499062176415851f1d33f31818869ed99d3442bca481a17f5afaf3fe1e"
    $a15="ebe0372ab9e479ffcf37de8d8807bb063aebe962918b8bb6114add1f1a3b1061339ef4499062176415851f1d33f31818869ed99d3442bca481a17f5afaf3fe1e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a3="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a4="8c53ee5f5550d1780fa9b188312e51356c2557ec2b42e6ff4629065ad122d959"
    $a5="f131554f0d1f881882e0fd220e72493303b24f48c9ddcf6677021a22048c47bd"
    $a6="636485868971eac5aca33c4a0e1800a8a11d980bcf0e3776b31002e2c5db91b2"
    $a7="636485868971eac5aca33c4a0e1800a8a11d980bcf0e3776b31002e2c5db91b2"
    $a8="8331934c92485666371bf055722c9474f157976d06cd300717481aadecbb29a9"
    $a9="d30a5f57532a603697ccbb51558fa02ccadd74a0c499fcf9d45b33863ee1582f"
    $a10="67bbf4879bdefd3e22c2362623daa005ccd10d17e037e0a3d3c09484b4f03561"
    $a11="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a12="67bbf4879bdefd3e22c2362623daa005ccd10d17e037e0a3d3c09484b4f03561"
    $a13="67bbf4879bdefd3e22c2362623daa005ccd10d17e037e0a3d3c09484b4f03561"
    $a14="25aa32e90623306ad05845b68d15e6f6c58432213dae7abfa7fd5dc04c7eabb1"
    $a15="25aa32e90623306ad05845b68d15e6f6c58432213dae7abfa7fd5dc04c7eabb1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a3="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a4="3301bd06d3485af0a0df4bfcd1ab65da77d62778fd062308d914378829b51f9af4d6a34d4e040ad435e543d6adf7c3f458baf920f1ef22b72d6134985b8bd89a"
    $a5="d0abdedf85b83b683640038be19525a4ba78d34398117a357d9098430fe43a052aa9e4d80b3f17934052b61e227c8f434dcb00c47fcf5524d583172d8964514d"
    $a6="10d64a40345dd323b7018e4613879a2820082dbd988d97a3f99a86c798ca65bb0d467c65a460965922dbd7a2355d07d3b2bdea1bea7b2db93c64e1c96d77d366"
    $a7="10d64a40345dd323b7018e4613879a2820082dbd988d97a3f99a86c798ca65bb0d467c65a460965922dbd7a2355d07d3b2bdea1bea7b2db93c64e1c96d77d366"
    $a8="7225ad998b13bc884bf5b5aa75d5841d8942c84981baf5f822b192b7b51b69cbff817a2fe9d32ce839254c580e54dfe25240fd12e4ec02a91a54ddad9ef5de70"
    $a9="cf4b2774a5edc903d52d8882676571f62ea4057baffebf387a2d561d7f29cf4978b7b2448c625455d901e726279fb7e033d5769f50488a5cd0978f99b6d8ea31"
    $a10="4cfd51b33aeb5a046c71a3f315cc5b84d20ea1066e92e9f3ec5fc8db10068ef43268543ea13606e230675db965e44bd878867c1b322856a0001bbc7f6545aead"
    $a11="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a12="4cfd51b33aeb5a046c71a3f315cc5b84d20ea1066e92e9f3ec5fc8db10068ef43268543ea13606e230675db965e44bd878867c1b322856a0001bbc7f6545aead"
    $a13="4cfd51b33aeb5a046c71a3f315cc5b84d20ea1066e92e9f3ec5fc8db10068ef43268543ea13606e230675db965e44bd878867c1b322856a0001bbc7f6545aead"
    $a14="3f829f7c771728a8ffaea8e41ee440282b5376b001c3dfe7b73eef7b2fe8cd033c953dc66b74462d40f8623b8a1b15fdb875b1ae7c97d00bc5d22c8c2fa65c5b"
    $a15="3f829f7c771728a8ffaea8e41ee440282b5376b001c3dfe7b73eef7b2fe8cd033c953dc66b74462d40f8623b8a1b15fdb875b1ae7c97d00bc5d22c8c2fa65c5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a3="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a4="d9fe28194265c84ad597e00165e52f3a2e99a3c63e49bfec11c039d06eb295e2"
    $a5="677a88031e7189bdabfd74e5d736f7b0a9069deb15b88f7f5d85d7234cb7a481"
    $a6="d49b4d32ed403526cc84ff6a1488f72cbe6883cef104fcf00387cbe9e27f2aae"
    $a7="d49b4d32ed403526cc84ff6a1488f72cbe6883cef104fcf00387cbe9e27f2aae"
    $a8="9c5c68c24419b1b6388b6aa6e8918e613da4538f8376dc6ae106cd45a598f456"
    $a9="4796448e5d4927d61af5a2ff073fb25047bf891ff43a2f0637021307a4b5f90b"
    $a10="92a3801d682634e865b12928034cee4ffa7fd42ff464c3098c0acac188133642"
    $a11="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a12="92a3801d682634e865b12928034cee4ffa7fd42ff464c3098c0acac188133642"
    $a13="92a3801d682634e865b12928034cee4ffa7fd42ff464c3098c0acac188133642"
    $a14="94d3f970ceb5bb584e0d484217efd29223a545da1f0921ba26ddad2767dc9e2e"
    $a15="94d3f970ceb5bb584e0d484217efd29223a545da1f0921ba26ddad2767dc9e2e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a3="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a4="5acff48817eb3b6d1fdac91d6d5b7aa8b41aeb9578315bc18f03148e"
    $a5="ae9f7a6af2b4e503b5f6f1aa848e85c59383373817ba24ea9cf87a66"
    $a6="048650084a17424689f234c16e30bc710f40de388536e24283c86dd2"
    $a7="048650084a17424689f234c16e30bc710f40de388536e24283c86dd2"
    $a8="9ff6781bd68aab282a8cd5e204d786ac4015ead2d01d94617a966304"
    $a9="66fef3e134760b5566d20969354052c4b085733678c2a49513ca96d1"
    $a10="b33536a4cf58ca8f8033bba1389bdba58c9a76aabee492dfd7411e1f"
    $a11="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a12="b33536a4cf58ca8f8033bba1389bdba58c9a76aabee492dfd7411e1f"
    $a13="b33536a4cf58ca8f8033bba1389bdba58c9a76aabee492dfd7411e1f"
    $a14="44b088f65bb1d675c5de5989d1dd7ddd854a54b85309cb68317beb62"
    $a15="44b088f65bb1d675c5de5989d1dd7ddd854a54b85309cb68317beb62"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a3="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a4="e1c7998de2ae401d0782b88a14ffa4cf36e91ba1fe419363c145f3cd257fea68"
    $a5="eaae764e4df8101af64d11ca89222cff01ce9f2a42bd24204972fb22da6f4df5"
    $a6="6913426a18b7a2b8e1e56901ce29f4cb4591ac0a6b16293bf89a9996979bb8c0"
    $a7="6913426a18b7a2b8e1e56901ce29f4cb4591ac0a6b16293bf89a9996979bb8c0"
    $a8="08da9c451c836b31b52693eab161e2858ddd6e932fdeaff1da75249db3fc46ef"
    $a9="79dc6d9ffd8fcf7cf9fda7b560efe726de6c73591cf15f20435767fa444efa0b"
    $a10="740626735fcb2bc2e6d1d053a08839e662e1b742c48f6b66e6ba3d0a0e5b0149"
    $a11="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a12="740626735fcb2bc2e6d1d053a08839e662e1b742c48f6b66e6ba3d0a0e5b0149"
    $a13="740626735fcb2bc2e6d1d053a08839e662e1b742c48f6b66e6ba3d0a0e5b0149"
    $a14="6d26e46be53f0fe7ef598ac735921bc632adafb06495e3cc8d5b8a000d2a43a3"
    $a15="6d26e46be53f0fe7ef598ac735921bc632adafb06495e3cc8d5b8a000d2a43a3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a3="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a4="21cbb085b4ce02709b1675982cf5ce4746f94f1904fad6bb8aaedb15cf930a1f41da52d79ef035a728b388458978662f"
    $a5="8406dc06cf7a0dd50e5aaab4cd139cf4de13c443cefafe8eb5e3f33b2dcf25b352fa727efa7040a99ba3c242be594c42"
    $a6="255eaaa0c3500178d298bdc7a8cf838a0325a42219ee399b637d127fc9e905100d993eddb0d3a7946c886ee5b778e595"
    $a7="255eaaa0c3500178d298bdc7a8cf838a0325a42219ee399b637d127fc9e905100d993eddb0d3a7946c886ee5b778e595"
    $a8="f2b6125cb326430278414ae56a7ec1b3e799479d172c481a0e2e7250b616eca4bd3cae12ab4f588b44468330a463239f"
    $a9="e346c867abaaa932275181b81141778226c6499e1db02e982edb89458906cc41995bcce2c0931e31e8fbb4525b701074"
    $a10="887c3e142959c3e9a58ae96faf9d85169d2f50f7f05672e13311d5631b73d4e4d7678df52b99b560ac6aaa47b18ef5a5"
    $a11="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a12="887c3e142959c3e9a58ae96faf9d85169d2f50f7f05672e13311d5631b73d4e4d7678df52b99b560ac6aaa47b18ef5a5"
    $a13="887c3e142959c3e9a58ae96faf9d85169d2f50f7f05672e13311d5631b73d4e4d7678df52b99b560ac6aaa47b18ef5a5"
    $a14="5bbf4565114af861a43adebf24140520ec1495883c55ea4886bc6eb7c97a512bcaef86298878792f0d7130a65d9d815b"
    $a15="5bbf4565114af861a43adebf24140520ec1495883c55ea4886bc6eb7c97a512bcaef86298878792f0d7130a65d9d815b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a3="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a4="dc01ca560ea2644e4232bacfad5ddc9eec1efe742d78d05ec04d380a429c9aca5354081d08f100c7dddf0ace72ede5a3cd899f7a7aa54751467648af5b294dfb"
    $a5="74de1ba9332e7a704527759f67ffa17e66eb5a1bfabfbc84a22999d53f39669685c8648fbd93509545c65806bc81b43b6ef1273037eeda37973a3a5c26a10f07"
    $a6="15842be569bcb206b002b67c5e9f7f9a34373a43069870e44eedb93c270c3d25142a73496bf85d164a41cfc6f72c170d1a9a206ace8e2453ba22dbe237fe0915"
    $a7="15842be569bcb206b002b67c5e9f7f9a34373a43069870e44eedb93c270c3d25142a73496bf85d164a41cfc6f72c170d1a9a206ace8e2453ba22dbe237fe0915"
    $a8="37af09ce69e7116dc485328e29ed178888ba86c2a3fbdbbeb5290b987d78bb5d3ff6859de62b434812c768addcd2a6b9d6f98fa4a912384633eeac8a49d6ed53"
    $a9="d27f1d0975973a6da7d4baaded8ee04956ef9318e02ea058383911ddb85b85831092ab3a6e446bd4034b94fa8d4f344e34fcbe37619cd9a3325e49aa9c2b8da3"
    $a10="b0c9cedef88b21548152b42367e68380003dea6464df8b9a4950e23a73d87eb9579a2574e00b09dd5571dcb11e33727d240817463b4ec72d9cd47f99afb7e85b"
    $a11="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a12="b0c9cedef88b21548152b42367e68380003dea6464df8b9a4950e23a73d87eb9579a2574e00b09dd5571dcb11e33727d240817463b4ec72d9cd47f99afb7e85b"
    $a13="b0c9cedef88b21548152b42367e68380003dea6464df8b9a4950e23a73d87eb9579a2574e00b09dd5571dcb11e33727d240817463b4ec72d9cd47f99afb7e85b"
    $a14="e31ca32f678240300ece9a964fd5777ad310fad2ffbd7a37de7af31433169c54147b88f0c38a74f2dbaadb82c753999709f9f2fe216ac96458338f5eb76559cf"
    $a15="e31ca32f678240300ece9a964fd5777ad310fad2ffbd7a37de7af31433169c54147b88f0c38a74f2dbaadb82c753999709f9f2fe216ac96458338f5eb76559cf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_adobe
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for adobe. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="YW5vbnltb3Vz"
    $a3="YW5vbnltb3Vz"
    $a4="YXBhcmtlckBnZW9tZXRyaXh4LmluZm8="
    $a5="YXBhcmtlcg=="
    $a6="YXV0aG9y"
    $a7="YXV0aG9y"
    $a8="amRvZUBnZW9tZXRyaXh4LmluZm8="
    $a9="amRvZQ=="
    $a10="cmVwbGljYXRpb24tcmVjZWl2ZXI="
    $a11="===="
    $a12="cmVwbGljYXRpb24tcmVjZWl2ZXI="
    $a13="cmVwbGljYXRpb24tcmVjZWl2ZXI="
    $a14="dmduYWRtaW4="
    $a15="dmduYWRtaW4="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}


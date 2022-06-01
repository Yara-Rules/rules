/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6931b735d68fc8e9aab0b1547dc0fe24"
    $a1="6931b735d68fc8e9aab0b1547dc0fe24"
    $a2="6931b735d68fc8e9aab0b1547dc0fe24"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="4b482edf238f3e07a3e0c730e500a608"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="9e8e2db3bc5ed9dbf33f7bcd0ce401a7"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="04aabb082f9a36479d1ec1c71a42f928"
    $a9="d41d8cd98f00b204e9800998ecf8427e"
    $a10="06e3d36fa30cea095545139854ad1fb9"
    $a11="06e3d36fa30cea095545139854ad1fb9"
    $a12="084e0343a0486ff05530df6c705c8bb4"
    $a13="d41d8cd98f00b204e9800998ecf8427e"
    $a14="351325a660b25474456af5c9a5606c4e"
    $a15="d41d8cd98f00b204e9800998ecf8427e"
    $a16="efb01dfe5107493448cc94ac8b8b4586"
    $a17="d41d8cd98f00b204e9800998ecf8427e"
    $a18="f0a4025b3b49b3e256004503ee31df8c"
    $a19="f0a4025b3b49b3e256004503ee31df8c"
    $a20="1f6f42334e1709a4e0f9922ad789912b"
    $a21="d41d8cd98f00b204e9800998ecf8427e"
    $a22="1f6f42334e1709a4e0f9922ad789912b"
    $a23="1f6f42334e1709a4e0f9922ad789912b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha1_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8605c4f2a895654f392416e343dc600d7a38396f"
    $a1="8605c4f2a895654f392416e343dc600d7a38396f"
    $a2="8605c4f2a895654f392416e343dc600d7a38396f"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="7f3ce53481f0d78173e13ac6ab96f49fa70e7aeb"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="6668acef4dfdfb88ac3e20a1ac2f49aeb7ee2969"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="991319bbeec4f8281da95529215dac1dc82adf99"
    $a9="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a10="2da0b68df8841752bb747a76780679bcd87c6215"
    $a11="2da0b68df8841752bb747a76780679bcd87c6215"
    $a12="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a13="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a14="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
    $a15="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a16="1b63a3772370841ba740989e2437bbaccfeff62c"
    $a17="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a18="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a19="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a20="a9bd7a5b583cbe082e2c850595c71a6818626f10"
    $a21="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a22="a9bd7a5b583cbe082e2c850595c71a6818626f10"
    $a23="a9bd7a5b583cbe082e2c850595c71a6818626f10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha384_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a1="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a2="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="a81e3f06b114946733b5c8e96380712ea45b088529f90fa1052893357743b735b6beb702d80bd5c830af6453fc9b6a6b"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="e7e3570a9158f5b0742229631c7b0e9dae37a8dcfc2d5216b814fd0bf6ab32b8b8d0110fd17944d7ce61b8101d9fedba"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="a99cd8a4174fe204ecec89b64395ee9deb133ab4e908394531c82b5607c827e5e4f81d8888f1a6cab611ffa49d144207"
    $a9="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a10="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a11="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a12="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a13="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a14="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
    $a15="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a16="b784ba41ccc59ce0e1fff47ba3c5283dda2d07f57f2fa79f44d0af7339fea71dbd4a0bcaef8bdc591dd379a29f2fa291"
    $a17="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a18="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a19="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a20="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
    $a21="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a22="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
    $a23="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha224_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a1="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a2="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="d2b010274fda47f64fd5526f089c8b4a8e3bb3ee262f47b80f663d1c"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="2dcf1fbb30c3caa6b3e9199be93cf544d886a6560c27d8fe899da9d2"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="180a1311fc53779d7505510b4ff58b4c43693b76a89a13fd590811b5"
    $a9="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a10="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a11="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a12="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a13="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a14="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
    $a15="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a16="0d8c8bdd52e8dd3bdc5ad30f5a490c85378ab4b4538a4d4d09dea5a7"
    $a17="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a18="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a19="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a20="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
    $a21="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a22="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
    $a23="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha512_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a1="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a2="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="61dd18f878f9babee88490bb6ac20ca15ff3f4e3458567f0f203b7ab8f4fcc1b75934e044a00528a312534ed652bc74e12fa22d3231e30441dad817b2a29de8f"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="bb59b5e317121d06b74b236df77b8133f0e2a68980f62e142107f4fb7ab4d65428f4ecb2ccb161b95b77cb2e5b2eff2035663a3019a6d30bdd1ea372bb17a0f5"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="4e7070be9a9f50084e638eef9b3e94d781902d497cea206b1a5653e6fd7547d2a786d87721dd088c638480859a61d120e9ddfb93a4f7396331cfdb0fd18daff3"
    $a9="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a10="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a11="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a12="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a13="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a14="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
    $a15="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a16="3e81141d297554a22953ae177ac4964e09d38125affe4c645afbe3baf6f392985c4f9949532940e328096e282bcaacc4ed0eae5e79c5fbdaa62f9af7ae15351b"
    $a17="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a18="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a19="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a20="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
    $a21="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a22="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
    $a23="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha256_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a1="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a2="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="a1efc3f5b9f460bc0f8ef25dd4f4eca8076bb0bdb862e11d5fb7f42fd41d240e"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="03bf7ed2e567521c28537c6098fdc329de9be921551984e4724d0ffb0a5dcb77"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="ab7e31925394b1c097542c068e21dd2b889cfc4ec21028a8075937be7f466baf"
    $a9="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a10="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a11="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a12="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a13="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a14="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
    $a15="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a16="5d2da63d1eaa9a48e937cf9da051ddfd3da578890a062053b48aaa37dd2bafd3"
    $a17="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a18="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a19="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a20="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
    $a21="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a22="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
    $a23="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2b_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a1="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a2="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="6388bd4a3de17093c15d84384ec1eb55072fb978cfc56f956fbbb808c79ad45b3eb184a627a6735e02724e575547eaf3e81d24e7d8e3be3dc6afa00e07c7205a"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="9e8fbea7030e35900b37c5152e9331415229237c0aa950177f6b3773a921645d7c62b1eda7c8afe2a8db8bf387cd5fe111c3b51a6a3c3118cd753670430b89b6"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="c3f01717507fd51d2d082c0f17ec838a451c90fa06305b4bcd2d8180f2ae5c40006a0f20e22c574b79105846b4ce4d1eff28bb831652fea7f10b8fa1b59aefd1"
    $a9="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a10="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a11="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a12="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a13="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a14="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
    $a15="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a16="e7691b44b817b2ce1f3edec2f108e274973c7b449aa4a5eba41b33b37b81817cc1c375afef945dbfe2bda499092bb5b5a7226f17c52f09f684ea5d35ed2734f6"
    $a17="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a18="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a19="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a20="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
    $a21="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a22="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
    $a23="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule blake2s_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a1="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a2="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="998054e44f83b6448227747dc98e864b08dfec1a28e9c51127b0bfe38d08bd19"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="bf3264707a6bef2e9e0b0614d5858bfc584000a49be8d8f2d0d711fa8214af9d"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="efc1407ed91a29128c71652515de2a326bef5d0316fffcec56772763b1cddaa3"
    $a9="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a10="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a11="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a12="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a13="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a14="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
    $a15="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a16="e15f1700710a12dfa16dbd330db733af41ff3b36b4e79a2203d8e7efd6a1e39b"
    $a17="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a18="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a19="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a20="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
    $a21="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a22="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
    $a23="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_224_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a1="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a2="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="04589ab9a2e8a4624a9fa1b93c070fbf0a52e68ef1eeb37c0426bf67"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="5f5aa48f5697dfd18e6524b2f258475fd9f78900188d07878f8b89df"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="fe25890f614f9c2b7c542e49c619d6fd0ec034c24d5759d9e4410e04"
    $a9="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a10="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a11="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a12="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a13="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a14="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
    $a15="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a16="8e68a832f9d600b58a6039f411205525e857aea59c35fd895df41d65"
    $a17="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a18="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a19="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a20="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
    $a21="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a22="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
    $a23="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_256_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a1="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a2="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="7c04d4d109db41e27c53ab13c7042b405167da65a9195be0de1f5e02ce491ac2"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="a9e843653e3a5da897f62382e9a2b74ed43f92ab99710635814624d7aa12673e"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="db5ffb26a1ecac297974aaed142088523bade501c0b44f3380cc4cb732002ab2"
    $a9="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a10="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a11="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a12="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a13="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a14="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
    $a15="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a16="7499680445e2395e08de22c4fba1198510e42408caacb306bf75aef8441dbc87"
    $a17="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a18="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a19="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a20="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
    $a21="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a22="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
    $a23="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_384_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a1="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a2="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="e417ad77ae1def150bb2fb75d6c2b6383c576779de430f86297eae46d0a2c4ffe23185e619a509b6ee1b8c61c37f5413"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="d627483cc795caeac912034ff700ca7d5b3d057065017389f99b10b130dbdd9c8d24fd8fbd15f56deece72fb1ede67f3"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="7a9ee0e56b09ff481562e30b802a2166697cbe4f058d2f76f0b02d972fdd09702a95c5f84a7dc4146a2774da720c358a"
    $a9="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a10="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a11="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a12="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a13="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a14="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
    $a15="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a16="65d8f08d81a546637d1cde6035f3bb6203508216303f6e36c503e1abdf2068f1b28baa87e2556c0e9e6ee3f43cf7cdfe"
    $a17="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a18="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a19="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a20="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
    $a21="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a22="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
    $a23="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule sha3_512_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a1="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a2="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="8721c40e8b8c1d9a94b90463a6e058a6afbaade33cc1a978554d05901c2cbd6566420053073c3f6eb3e640f57509740082867de6ef1c832388ac710c48c76171"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="5c985f072825af2dd329b7ff5db120e7f7cbda708ea538d37af2e36914796efc6b83c64c1a18dd8e5272f72865fcdf2c71db704092ecea6646f7a64a01ecf34a"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="2417abf3ef737372d33d1e45c7fed169b7de6cabf16c2da37c3153ef7e631c047bc7763c88cbe51bad4717c6d9e1135e2e3ae82550fadc2b3b52edd923decdcb"
    $a9="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a10="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a11="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a12="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a13="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a14="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
    $a15="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a16="ab04d897eb064132985963d7615622da0e5dff3d4519dfaab379be5b04a2611aa412c974cfcf8deff12212effe3133d890b49af2f2f2bbdd520e6a29f21a1e8e"
    $a17="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a18="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a19="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a20="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
    $a21="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a22="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
    $a23="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}

rule base64_hashed_default_creds_silicon_graphics
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for silicon_graphics. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="NERnaWZ0cw=="
    $a1="NERnaWZ0cw=="
    $a2="NERnaWZ0cw=="
    $a3="===="
    $a4="Ni54"
    $a5="===="
    $a6="ZGVtb3M="
    $a7="===="
    $a8="RXpzZXR1cA=="
    $a9="===="
    $a10="ZmllbGQ="
    $a11="ZmllbGQ="
    $a12="Z3Vlc3Q="
    $a13="===="
    $a14="bHA="
    $a15="===="
    $a16="T3V0T2ZCb3g="
    $a17="===="
    $a18="dG91cg=="
    $a19="dG91cg=="
    $a20="dHV0b3I="
    $a21="===="
    $a22="dHV0b3I="
    $a23="dHV0b3I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}


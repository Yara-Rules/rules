/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="94a391e7535162277a17a069254b24c6"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="7ac87e42d0e28da672b0ad402cfa3934"
    $a3="9778840a0100cb30c982876741b0b5a2"
    $a4="6ccb701e0ebd1bb3adaaa8b3cd00ebb3"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a9="53b76cc34444f5b08f9a0a333437e32d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83ed19ad9972da402772ed98a0ee69bf90747229"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="3249f1a7491e750be6bc3340a0186e7711cfd73f"
    $a3="2064cb643caa8d9e1de12eea7f3e143ca9f8680d"
    $a4="b4898eaa1b9518785646fdfee1860ca14811123b"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a9="ab0b22ab421c001462af4a9f382dc9284747b43d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a63e00c9e0d808ba4f68613c7ed7896ebdc4878582807d265e2331f832b62c2a72eaa4db07a5fd3a3cfa884b87367f9"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="439ece558fe24b03b63ce900cfb5e0bc894bfa395361307b42c94e8b1b03298cc60419aee4b09e0c128aec38638602bb"
    $a3="521e2117c8323e893baa0ce500a513ba635ad96fe3156a317c77924723aaa5859debf6b6e69ba44b7a2ab4724091899d"
    $a4="4ff888047dcdb8e2e52acc6f4aa04034177785385483c28e42204f016be2a79a89916530d62fceed03cd01779abdb3f7"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a9="0bf3b54dc38a203d2213b18247a7b72c22aeb37c969207af6df6bc8dd7f08accb84fe98e32445cba70a2653c9f7fdba0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1260044353482e541139f413b00ea25d4769fc5506c70cbd9588bdd0"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="f11aab589a3c3d46b38008381023298984bffe41cea7611bf8895058"
    $a3="907a4949f53280718e350989d9ea03f7d3ca870f1dec9cbc40f3110f"
    $a4="731fac56cc1354c66eebb30c1933bc7e40bab821233407e28f55da6f"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a9="02f771f74780e4827cfef89afd1497da13352697fa89b27db2238aca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="518b202e6fad9d16935f64821f2215b578a5f30f3f1cd46dae95efd3fc913014b441c1e517188d9d6aa53cf85c447869bdbf2f52780fe804551de10bc71cad37"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="528036fbe5a60298874181839fb37d70233dd65b8bb0761c7b0ce44242e0eb302a472cfceb5101b89487fcac90de294ea3f47893220d325bc293c46cd93d5796"
    $a3="73461cc279e0e1b0d11ba54de652ccc047567f5380f6d6aa6f4f819aab92eaba19a7fda16ea0e6abd1dcd67d42b0928e2fe68a3fbe3afec7dbf325cab0abb364"
    $a4="7e39b2b69edac5d3c761dc0926ac131819d66aa66537b2d1af5e5ccb6a3b3c4be81c3da8c7d3883d2e37f44069c11c51b0c16e4cb97cddae3e9004ddad85ad82"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a9="86fb3bdfd18c375e452153b46e6ae45bb1e96aae0bca4ff19adc93f474c85f6cb6cd8f184fbfaac56e00df0d7cd480998959769aa0c206227254b62b1f29fca8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1742527e408c117e0f3e1b1138e8e8ced53233e4ac829d29fab07fa34fdf2da8"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="664acdf6ca619f7e9dfcfb667586997040abbba480ef555b2e79a6a9674bca7c"
    $a3="a7056a455639d1c7deec82ee787db24a0c1878e2792b4597709f0facf7cc7b35"
    $a4="81effd3cf0ee2e5db583a74343fe6499edee83b535b34858739b6c7f85e747c4"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a9="3b3927e40c6e2d6dcd4ae074e706611c76b920cd6cfbd0031e70c13029a0c7d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22949e4beabb3c2059aec71ed77ceab98c81c90266121957a07aa5412625077571bc6d516688a0f36f72683137618141360893800da58eaa8be6ee88d09d15b5"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="2a4e20a06c9af62af6ea2eb6b070193672690016d0554d0479f0ffc0fd277bedf257618320e3c7af3d8bea6e0cd5d554c9c6bca7c7e05fa09b0bdf7f6cc72d90"
    $a3="2e61c67977e90d04fc2ba0130a3a1ece4b4509afdfa9e58ad706382cc2ec1a94b64d014fce3c06f193bd983afbd2247034627d6c064762b30b983a52e7a4945a"
    $a4="731ed1ad45779cb6b1a24e77cd08c6e9eed4e48bc3c95ae8e4c93f27cddf87c2df765f1d1e6806f69e7784b1b874839d9308a0d135884162026da2de6d1a5bd1"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a9="8187cf141f305d411400cdcea12f9f947260cdf5e342a8cd2a31386b2bf30a4d4dcb96874a528ef7d010a3e9ba4f0f1e95d7b6e81d967a6c4d763dbf36d7e11e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4f52828cf6fb32c48163e41d4a81f3407824bb71560e4c05767926883a43dad"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="97da8c4c23c3c98b0495850e1a2d831648deccfadcb9897cf0a7d9da1bee7004"
    $a3="f645ae114819272a88025c3b85c285eecd80d45302d8125fd1e27a7c90f84fd7"
    $a4="3a473f9aeb71569a35fa3abcd46b7471448786a412632ce24fd6421f0c2edfea"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a9="296a10c1711fe7f1786f3fae5fe592a6f6d2eadbed291c7d26e516f2e6b70532"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4086c6a76a93dc4af93481596725ce3ea7337af0edcf26abea5ea5f1"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="897696d9785a5efa0daa10288d85ed8ccd3314f7cb4efba4f4ca2055"
    $a3="fb3a50b379597148370a08cc0ce1c02cde17b138dfc52a118b1ac4f5"
    $a4="f9a39b020f4960e18518528a894d149ac35820db2a8fa3f902bed1db"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a9="d6af525f61d62899149d0730cec3b754fcf4ca9e1ebf013dc1dbe920"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2cb32f3cada36cedfae3c2e97727e16c90c76931187f023f5b77171a54bb97af"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="8224866b82c8e5bd61873936dd988b02878f819d4d891a8b8325e5ee97940ece"
    $a3="bea26a68f1c3a2276e3e88002800cc5d269598edf4d618c89e3facedf6792158"
    $a4="7a42ffaa48bde0bacbe1a8166bc766342e1ccaaaf59f566c1427edcf16b6d03a"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a9="a381c0e0dbbe117c6ae87d9ddebba0f126acd395cee9ad6e7e31f96920f1f458"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c522c7230f5c896518097c489f423f2c6400ffe03d670a5215fe37c14be48d92a5e7126c2a25d7fd3bbeaed73546f6e"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="2e88d0c3103abe99dbb748ae1cd719c2a1df734494a398e6284de4a497fd60774b16deddb0b6e1a36f5c715cbdd275c9"
    $a3="12352f148b962be3405fdc721550dd617e9d3b97b038ea6f0219df002dbfed2a1e83842d6b7b2c426589cf3699f5ab55"
    $a4="d98c93bb9bc3b9c9bedd48450611677be61ed1adf16f979ba33da1a71b52ccd8a213f438a5d7d05009ca663e545e3781"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a9="05488b0218445ecb3d45325f70fa27c4867f71a78236deae14a4299a082ba67de1d52dfa2c59cb227e1ed16f29b65e8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e449496e3fd89195837ddd58c45f75cbba551f8f5e13e40da05c8fa01f8ebf0161beee115588c551c9addb22b8eb561127de6111f3064f5890e41099d1f10dc3"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="2b165fb340db361f9351ec845a3824bb58317f65fa91dc6070e89400520e3daa20b0db0627f67847b3da532c4cbe04ca63900de44d384d1f90c15ace0bec73b1"
    $a3="2b2aa94b914d29b3c350ba58b4bc7108f8169dbf26309ac5ddd439421803a5bfe26a9665fce60fdc20348a2348d86a909eaa9d6921a9bc6c9daa8b6a4433e68c"
    $a4="cc1179ebcf7c8947ba16d61efa3d9c3b3b05264e509f590e8d292f7826f33b6b81450c03735cc7c910a5353fb962bcf8b41da5eb793f06bb9a64b2ee768c2bd5"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a9="95f5013b88e0c0e71f9741e05a0973e852ca28770c3ed813f7edd7f8583add711442ffa2451cb90a468aeef0502a77828417225a758a3f4701e6502c8d450a58"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_sybase
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sybase. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="MTIueA=="
    $a1="===="
    $a2="REJB"
    $a3="U1FM"
    $a4="amFnYWRtaW4="
    $a5="===="
    $a6="c2E="
    $a7="===="
    $a8="c2E="
    $a9="c2FzYXNh"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}


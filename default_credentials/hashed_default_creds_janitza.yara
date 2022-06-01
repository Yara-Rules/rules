/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="5dd6f624e3cde0fb8e5e6d63c85ebd46"
    $a2="084e0343a0486ff05530df6c705c8bb4"
    $a3="5dd6f624e3cde0fb8e5e6d63c85ebd46"
    $a4="c7bb23be6d0ed7badcd1849e3c38ad41"
    $a5="c57efcb10633089877fa7ca6959c572f"
    $a6="ee11cbb19052e40b07aac0ca060c23ee"
    $a7="5dd6f624e3cde0fb8e5e6d63c85ebd46"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="5d6dd51fb8f76158f084629b37f94079a98df6fc"
    $a2="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a3="5d6dd51fb8f76158f084629b37f94079a98df6fc"
    $a4="52128b06870ba981c1e894ddef21a5c004413a79"
    $a5="9fc237feb3db61662a5666fea2fbcd0ce327bc8a"
    $a6="12dea96fec20593566ab75692c9949596833adc9"
    $a7="5d6dd51fb8f76158f084629b37f94079a98df6fc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
    $a2="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a3="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
    $a4="4c51d7b7b820219e04493fb7c2e59a7443813fb85e9b5cd8ce92ff74bc7a0997bcab1ecba89697e8f469850bbc4d0056"
    $a5="5884c6cbf279b37b558b341666d4fda8fe0e35f649d383e417f8a301e94d0bb50f7c8ae807617e017f78aa84c01f69d9"
    $a6="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a7="a56b5020d0f39e20775e6b90bc535e76a55e1309c31ce3199f76c7ddeb0a3584827ca41a692fa6a1ef1b0b5d37181715"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
    $a2="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a3="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
    $a4="2857183a6807620c353a06f18c7652c4f8e63c7aac29ba79e84d2e55"
    $a5="95e95c8a6c039e07ae1711a99c0cfc86e132c573fec7ba4869bf570b"
    $a6="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a7="9ab61df03c57e4468e81dc5dacd29a3be2d6b88f6d8805a47c3d9159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
    $a2="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a3="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
    $a4="df5980b2e1c38bfad3c84ba9a06d367906b9a4f34e6571a1c09d5a3c8f50f7c60f27f29a8d4a87235ea830ccc6845a39cd090d65842827f911650b58f2bf6e65"
    $a5="a16eaa57992dc179b0fd1c8084a6c80a48341b45af5ba1e6b2f5db10ae73ae6a6a9094f7c422560442250d8e4b9901dba0920388f25db6b46faf91554dabe776"
    $a6="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a7="ae73deca5149ee0b04cf85b901659c48415e8abed5b0a9f4aedde97fb0d606dcb74b411ca350c8eca8bdd370ed1ce613dae2a8c9b54ea632f1abec285e47a9be"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
    $a2="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a3="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
    $a4="5aaec4a266c3827df7d1947ea236207cb83216315efd056b44b9b81cad7aba0a"
    $a5="52a62f75e5b83b91e706fdd8dfd88d2d6544b824d7767a2a38cd6ad078651a89"
    $a6="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a7="f7c4cb77e2c82be1eac2b6c4444410963be5b4edc55582c8ce17e50364e7ce4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
    $a2="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a3="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
    $a4="83acae50ee3c1005a9bf2201fb04346756185e2281a56bf4a73a5cf1d151fd785cb932f9bf5b30229548cbf98c40549b4b993ce1403da69ebedff5e07e2308bd"
    $a5="b1c5f49c045e587ef1a068b2f944c3ca0c388f46511680f1bd6bd5ad5fe2a9ab1610e58894c6f3cc2ea46a5462514349396340c61e278c79ac72d6e9f56c1661"
    $a6="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a7="515e81585b8440e6055ad7e37ae7b38621dcb0b50520feb6080b4351a7245ad936fe03554f194655420230d048d09fec173345148b7397d2d19f8135bdf9de27"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
    $a2="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a3="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
    $a4="d7f8339d68259de3f434ba48805e31a95dc469f26dc7d04f6f99aba404be49ee"
    $a5="d088bd7ef99232e4eecbc1b4966ce016af08ab217fad21567a3c19d9a27aff4d"
    $a6="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a7="cf666e156f39296a510f114fb17990c04523762cfd8d1a036a34ab96608cdbe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
    $a2="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a3="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
    $a4="2e5e2f7ca78996bf07462d3586cee50e70e6c09ceb67a6ccce49c378"
    $a5="9f5a4e1fa8c4d03581ec9b4bf4cb25b2a2c97d6303fdc2ec7f3eeeeb"
    $a6="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a7="17301375cf77f599576307495f8ffd78cb030e3f64fb65b2473c7a7f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
    $a2="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a3="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
    $a4="c83d1a8c35171808c4864d063d67975dca903349acfea45a1d995b7c588a80d6"
    $a5="78e8502f74b4be418b11228346f8fd12b60be9846cb04734faaa0c95433d70a3"
    $a6="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a7="6d447fb879e72f03dbb182407315ffc3b2241acac555b0d0f5a2120febc66bed"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
    $a2="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a3="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
    $a4="f08e5149e33ef3fa24c4c2e771aafc9bd82de40271c35df683174533e68fed7475f9f043db6453b974aa90e7d55d4ce2"
    $a5="a1156686aacd668f3e52b8b83e20176ee6a5c7ec9939f05b0ca83dc24ae9693164f1d33454e3961f27c03fc4d4a85f8d"
    $a6="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a7="cefa764b8c811d5ffc70fbd932bb112bbe2b26985db5117bd3d2af4a4058bae267cffd2375291bab37951225a2f6a2d1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
    $a2="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a3="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
    $a4="18777233cda4eaedadc4b6b1afcaa7968f7c8b048ed63a1a0ffa1141a2050213f9319c543e103dc9bb3079cca9878d55365735c69b9a9ffb321924a2d6a6f5a8"
    $a5="b22ec99e32ef6a5330d378ab0a170c9b0025b400e33b302851a18233448f176af52c98d62cae41195edb76c15363162a10c218330d82f3473bd322c5765fa10c"
    $a6="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a7="3454a88a4ad5b7c42bfb8c89e143c3834ab3b3cf44fa2471de97781bec510dfe96e7809fd7dbd837900493d51a1f0ce7204593b1d81fd6654be6e01cc6b8d4e6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_janitza
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for janitza. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="SmFuaXR6YQ=="
    $a2="Z3Vlc3Q="
    $a3="SmFuaXR6YQ=="
    $a4="SG9tZXBhZ2UgUGFzc3dvcmQ="
    $a5="MHRo"
    $a6="dXNlcg=="
    $a7="SmFuaXR6YQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}


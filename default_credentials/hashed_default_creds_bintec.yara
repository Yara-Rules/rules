/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="ba7378764c1eb4f960f228b99df48ef1"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="bf4302b914c2b60ad4586d574cd6dcb9"
    $a4="e3afed0047b08059d0fada10f400c1e5"
    $a5="bafd7322c6e97d25b6299b5d6fe8920b"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="89fe3e5876068bceb87304fc3b710a93"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="268c47f843d93c58480f67e84c54d0755303f64e"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="19245a47f73a1bdbb59babc52d8266fc75d7c7be"
    $a4="4e7afebcfbae000b22c7c85e5560f89a2a0280b4"
    $a5="816c52fd2bdd94a63cd0944823a6c0aa9384c103"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="f59f9f90f61946a142ed347cacb8ddc03eed5d40"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="21bcd754b7a0edf18d107852857a59ec252e1f99e9a8d35c7bccf81f295ca085fe1b140509439df467ef5917cc7d17fd"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="c4e11f026a6e689252a809110c8356add5b25642230d49f3c00a7f5dc58f26bfccfd40ecd227e834c0416045a73d6f2d"
    $a4="cb25ed2781626b3ab0c1de865e7cc7e6db8908f6d6046d96a284c8f95e1edee6da77588358648e0508a7725f1a777778"
    $a5="4c88a9f3e84234bbed809d07d3bcfd9a053607b261ffdfce2dfb45b703430c28beae1470a1f35855e20b5a5ff394f220"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="c5fc7e2afb93786ac8b2fb221162ac0e0826a22d481aefbf01f7cdd86eb2c14ccdee61dac002e92661999d4aef5e640d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="920f974da72d1c42326f3c9a4a118e5bb5107aa5ec8b3c6198369d73"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="2ab8e1e7d27d5757f0d2bbeb93b0eec61df9e2feb70fb2d688e74a6a"
    $a4="88362c80f2ac5ba94bb93ded68608147c9656e340672d37b86f219c6"
    $a5="41f55144ef67976dd919d847c6af062aa305de2d2807a275bf317e3c"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="a1bf7bd0c6fbdba7be761ad09740f6df7a298374173c19416a3d3f49"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="56319d24143b186cc31e9c0d873a8675672e7069bb7f919794d033f3b3e4b37e2b500a11eeb111effe4e61dfe8175ac2c728692cf3d0af8ef1b8bfd9842762c2"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="af6ff415c73a824bfb89739b48f33d71963742d9c8f4aeda504cf58bfb98f1e887c0f0b5e8b189d897368bcd7c240dfce5cb337d55a3b2764d682a6ed6b98423"
    $a4="887375daec62a9f02d32a63c9e14c7641a9a8a42e4fa8f6590eb928d9744b57bb5057a1d227e4d40ef911ac030590bbce2bfdb78103ff0b79094cee8425601f5"
    $a5="a145800e53a326d880f4b513436e54a0ab41efc8fdd4f038c0edae948e5ae08d2a7077d5bb648415078dda2571fe92c4d6fa2130a80f53d9dd329e7040729e81"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="19f9adc9d1a3133f26bb673ae2f3cf1c29f10749db5306ccf6268a32509044231093e27f3bd6eaa573fa60f9543f79043f4433cbf851ab6bc8299eea3e4fc006"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8db24da5855f164a53ed460b0d603468d9a73c1709bfade0b2d131229743647a"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="e2fc622593935b064084169db24fb6ebbae612605b0efe49a768a540d78ea04d"
    $a4="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a5="1ea442a134b2a184bd5d40104401f2a37fbc09ccf3f4bc9da161c6099be3691d"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="defe840f8638f4b6c5009dd9945404b279fd1e884c8825d9ccea1120563504c6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="b4f8eb712f1b36d673cd5d67fb6597c3715b4c52bd8a63d9fc0856791379a7fd84deeec04d70c11fcca7e5bdfe950bc74cdf4daffab1c88ef07f129961010146"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="487359a72a4c885d147e60ad6d43d8a738bc7cc6fce1d628df33d8755574ef1e68f8fd2a225fb81697d002bde8e8591c808814baecb8a776efe1827bfcb5c08e"
    $a4="f6baa4e6ca08a6b47ef9c182f4af1301998798bb6c2ef7f410c828838f06e86315e419ffc39e7a2799fd918b33e155e03362f693796cfdc01dd269afc6a8dc4c"
    $a5="de42363405e1e34b996a45cfae3bbb2db5b0e103f1b0cab74641a2f64e64c317a3e67bae59320795741806f482b26202d8e2dab2a02cd2ad7c8cfc0ac5904cf6"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="b221ab8a2827834440fd7b14f3939987c70c966a62bae8017b1ae9dd80e084751ce5f3d307eb1a76627123cadbef175e0845c7d16f43534372b25009815e1739"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="45c063a26a91b200f726efdf577837cc040ebd4d660d77900b77cb292454c6fd"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="714239f10c6ac8224044d36c0f0dab36fed60c6cd6aa5935c125d1f5af0e827e"
    $a4="b422627f3ae139067c10b8625441567e61a8be06be00702cdbf249483cec98f0"
    $a5="f1ccc580d8ddebe1404dfd59b57a710a542cdde71ee235d4b019338dd98e570d"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="9aeedea1de355cc3db103c6ecbd73af17145498b4fd17c21745b1b838d22e7f6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="e37a7ca5f62f4c86e3dc11b460db893fac7798465f5cb9f4b2f2e3ee"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="80b35885f86c51945439626b539eb283e6fada204e33fcf521201b51"
    $a4="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a5="0b1d5def4f0257158dc6022349b17d0f19a18bed83b32f164e03a116"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="0b06356870aa8330d68590cad0115661bb4cd349c5b259689d2d180f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="7f103df5a0ff284c2a6f490e60cb9e52e03bd0b96c9c62ec7ead68af28fb8269"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="08fbc2c068a043308809de3d4b08dde004a3628490c2bb4f245daa4fd0e7e8b2"
    $a4="bbe53f6251b67bef7e6e8c008916c4c80cfdb55175e912c5ac50c73246425fb1"
    $a5="fe4247802adeffe38c89ac44f02b91baca3423c7f2bb951b685f586f97cf124b"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="f5d5daefe601545a2967a6cd9ec5c65d15394fd5dbf588b5c68687cdbcc0f7ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="cc69a08d275b075f625a74a92b68d59cdb18d26bc91d6f392757a925028e6a410caaaae5a2cbdf3eab10d44fb5c40ebd"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="fd08db8d575a4916e9d1a1820713b3de570aa2b4d7bd949af2750c4c3c02bd58e183f302b9da7d672a474d461ddbad19"
    $a4="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a5="c653a378f3b0f4530aec7b687affe546680b5fddd1247060b0e78895d92613f83f11d6d4e35aac659c6408230ae13003"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="278e6671e618a56842c0387444cd04cfc8ca45043025a803f54e65108bf9c280c8e91421553078655d67576a917c0ae5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="b62a614600841c8c1e49681d1b1ef9b077b553461d47da1942c706aabaaec008495a8cb88b51029283a9fd2fc36a1a6ecef9038e64b7adfc665ad5f4daf546a6"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="9d099b803d5c9d1b01580c68b3e4e351cc49a685cc1ebdc94cc03c52a4fddc55d735cd1ea0d6dde4a4134c6b918cac8c612a9bf7b779c7329663ffd165212ed9"
    $a4="44bae752c6d78e9db63821cad5772a9395ca13e30e0f0567681e8a09819641b9709445814aab952b7b6bbc0c32203c2671eec852131a4fca817b565ca73a07f5"
    $a5="51d13ec71721d968037b05371474cbba6e0acb3d336909662489d0ff1bf58b028b67b3c43e04ff2aa112529e2b6d78133a4bb2042f9c685dc9802323ebd60e10"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="a888322b1a103447da4691f9108d12e972b96aa58b52b42327d898f0c459531a2b4397a9a54e727811d9152b91248464a65734ab0ad4a4d8444d0d5b71047ffd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_bintec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bintec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="YmludGVj"
    $a2="YWRtaW4="
    $a3="ZnVua3dlcms="
    $a4="QWRtaW4="
    $a5="Tm8="
    $a6="===="
    $a7="c25tcC1UcmFw"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="81dc9bdb52d04dc20036dbd8313ed055"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="697efa94ad1e665c4d0edd4c810db6fb"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="d41d8cd98f00b204e9800998ecf8427e"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
    $a8="d41d8cd98f00b204e9800998ecf8427e"
    $a9="8e15625d6c158ec48f374efb77bd2714"
    $a10="d41d8cd98f00b204e9800998ecf8427e"
    $a11="154a3745a2a919c100a73a7f2303ef18"
    $a12="97876d07ec3d609a6edc5871f03a3ca3"
    $a13="97876d07ec3d609a6edc5871f03a3ca3"
    $a14="c1b21f4648771c46acb6ac65b762b3f4"
    $a15="154a3745a2a919c100a73a7f2303ef18"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha1_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="7110eda4d09e062aa5e4a390b0a572ac0d2c0220"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a8="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a9="6184d6847d594ec75c4c07514d4bb490d5e166df"
    $a10="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a11="c66c09a3d8e31036fd088a1f12aec347b27e078b"
    $a12="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
    $a13="07c8cd4a6a7d68a2eb83ee0768111f9e7b7931ac"
    $a14="2dc63eb51a5eaac95ba3af8b0375a4d783c2248b"
    $a15="c66c09a3d8e31036fd088a1f12aec347b27e078b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha384_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="504f008c8fcf8b2ed5dfcde752fc5464ab8ba064215d9c5b5fc486af3d9ab8c81b14785180d2ad7cee1ab792ad44798c"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="e063d31a6d256a31b2d1882a9cfc0ec4de630d4af37b6e8942a5cb1bd18b2af08fc937e773564b559161b670301d9114"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a8="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a9="38adaa6adb917ba1b192865623bffaec444e791b01d23f3e22eca220108ce3e55e3ad585f7e19144a353e13973a14df0"
    $a10="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a11="0831bfb59eb75eca8d74ed393b18044884d7b1acd54369255496570027d7fa4f8818fc888d191f2f3fd198ddfa5d45e5"
    $a12="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
    $a13="5fc841865fc4fd1d00c065392d3fd0b2a13b2914c7d00fb6c81c81e0f5a3ef9d2f2af82f56a330b2e24d00dc3a2383d2"
    $a14="392b0f28a6b7827967a93a52306347a74c51f2db12c582546008c7a3dfcc3b9d11c49b0bd7ceae864be4e55020b336b1"
    $a15="0831bfb59eb75eca8d74ed393b18044884d7b1acd54369255496570027d7fa4f8818fc888d191f2f3fd198ddfa5d45e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha224_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="99fb2f48c6af4761f904fc85f95eb56190e5d40b1f44ec3a9c1fa319"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="3febb630e97a4b8be0b40acbeb4edbd88a1483c57187f0493d7465ec"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a8="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a9="571517432a4427e7de7d91d9ee00d811e0b280e42e0d931297341cc7"
    $a10="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a11="b12d3ac8ee3f493c393ac2283b41b878476773bf7ac110a7f851455e"
    $a12="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
    $a13="ddcf4af692370322c72858c21d6c91b53f1b95b3fa34767ddeb5baa8"
    $a14="89507e57477323f5d3a38b4ad4f5cb43e0713f827f9fafbb7aa59fe7"
    $a15="b12d3ac8ee3f493c393ac2283b41b878476773bf7ac110a7f851455e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha512_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="d404559f602eab6fd602ac7680dacbfaadd13630335e951f097af3900e9de176b6db28512f2e000b9d04fba5133e8b1c6e8df59db3a8ab9d60be4b97cc9e81db"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="acf4fd04a648ae5754053813e74c37ed875e024caabe9905ccff0441cd18efb969a58089ab4a60a51545f03ebfb94220105a47185a6aeaf108851cfc513cb7f6"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a8="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a9="c7503ab487c392e8cbbe756fd7340bd83214c351dfd48a2c597285267621976a5e321fa88923917b8a2fb6895727da0a42123233258b4da485b0de7c91ba8610"
    $a10="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a11="dc35aea6b82b5bb7152fe5c78ad7c87e38ae06f9b5749cd7e22dfd5498aa5f84b5b1bfa1b387eea6c4f41de2b14bcfca795a07fe420268945fb3366dbe81c662"
    $a12="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
    $a13="768232fcb74ab2fddea8bec15e6c845f11b6f79094303ba75481787291237982ca28e8e14a84045da8f3b2e5e9659ea285b7a1c7987172fdd6ead28cf40998d6"
    $a14="b1a522ae5d2b9b0738a182a7e16d8553ea5013b92a350cdc7fe7a870fe5946fee0bf267631a061fd386b896b54d5d3f76b09ecdcf0323ffc2fcd0a9a5b7bb36f"
    $a15="dc35aea6b82b5bb7152fe5c78ad7c87e38ae06f9b5749cd7e22dfd5498aa5f84b5b1bfa1b387eea6c4f41de2b14bcfca795a07fe420268945fb3366dbe81c662"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha256_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="4dd98590f9dcdcdddaf268f443300ec1f63ddc8fb5a72e7b4bea2c0e4cc57014"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a8="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a9="ff71cf74abb3ccb005b8b64371725db15edc42c1ad33413bbe561b2da3c85ef9"
    $a10="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a11="68748822a91ecad774e5b003cb902fce075190efb9d48b30e5c1f2c03b321ddf"
    $a12="87d342881cec7ed0cdbc447da129dd07547a89f540adb642398ba59e22af52fd"
    $a13="87d342881cec7ed0cdbc447da129dd07547a89f540adb642398ba59e22af52fd"
    $a14="f6b05a8dfc21ac45103a87a9c845a7b8f92e5c572d8f3607fff101d6daf17f65"
    $a15="68748822a91ecad774e5b003cb902fce075190efb9d48b30e5c1f2c03b321ddf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2b_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="da77bd2a1d857d88b31de27536b81df7f005027d4f847667df13a0569b6048e0454ce9480827789547cc174060c4f388866ebb0209929b0de414cc9ac571c421"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="cddfcc68ad850c35154c6aca1a70c03adef9d253ebeda58b91c3028b3fe44acfac46ebf6d90a80810389b249845137a758dc0ab0e64d0b5a423080b068325b9f"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a8="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a9="86940e2037b2fb33fe0318c08983f543243d4244488d8fc08367e0a032be1c5eae36feeb1ef3c9599d1491c50f94903ee5c9910cb4f160fdd69c2b96ec80a263"
    $a10="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a11="950b577e986853020dd0ed223ad7b34d1faf2eff2350ddb3c406ea1bbd73dd71c573e46f439d8a8ffb52928e69783477ab3badb9a33c7d0bd3a4dd59af4621d6"
    $a12="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
    $a13="ff86a58729d06321cc03154320194bd9c8de16777be446899c1575cb92e77a3c339152d163c9d29582bd542b7dfca28ab91dbfe7e1a57d489f18e7354e187ebc"
    $a14="67394b512dbcda224a2ef0749cdfbc0aeb6e4cfb22a14e348e3838559b9dd0c960a7eef0335512bbf2752a5100ebb04ec13b434e6ee729a3cea726526eb69285"
    $a15="950b577e986853020dd0ed223ad7b34d1faf2eff2350ddb3c406ea1bbd73dd71c573e46f439d8a8ffb52928e69783477ab3badb9a33c7d0bd3a4dd59af4621d6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule blake2s_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="90931556d9513e8c26040a9ec2a2f1300bdc79a890907da9cc2b3a2c690574c1"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="6fa71e9650b7541e9e5e75e67a434bc1521551a29ad163adb27b7466e315be95"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a8="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a9="0400b88186abf794f909f87c084891662ba79fe124332e0aa83a843b092e102f"
    $a10="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a11="73fd46d492aec5e03b0af7458e7f852c65786fb2650f28a1d8728a4b5c1f5a6e"
    $a12="8a35ca10a587c9e8ff45f08c13fe45fc5d0d4233341b58f8dfbe1ea361387f19"
    $a13="8a35ca10a587c9e8ff45f08c13fe45fc5d0d4233341b58f8dfbe1ea361387f19"
    $a14="ab2ad7b24145b8a9b326fff780008611d381bca0d751e914511c3ac974257eba"
    $a15="73fd46d492aec5e03b0af7458e7f852c65786fb2650f28a1d8728a4b5c1f5a6e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_224_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="b0f3dc043a9c5c05f67651a8c9108b4c2b98e7246b2eea14cb204295"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a8="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a9="e71ee98ae9e0fc79ee1966cb729384bb610768823d48288cf4a74bd9"
    $a10="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a11="21c3945f6418df7177b27fbc54bd27f12cb7e8633f2b28044008de2c"
    $a12="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
    $a13="23d8138b9b97353676e81615f06e359497faca5a0224548a34e7ab6d"
    $a14="632320d4c1e678748f6314f75686d47ab31ec31457fbf307f995ca97"
    $a15="21c3945f6418df7177b27fbc54bd27f12cb7e8633f2b28044008de2c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_256_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="1d6442ddcfd9db1ff81df77cbefcd5afcc8c7ca952ab3101ede17a84b866d3f3"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="d99cff6dd5fd907def4381b046a27dca74dc887b3c1581e74c16b46543443c46"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a8="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a9="2094df4aa54e2d6a2aa85534c1ba01097cc580f57d8577efca5e11cbda8dc1cb"
    $a10="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a11="7655d678c888d13cd130845df4b7e77dfee0c691cabdaf7ee84c268fb43cdacb"
    $a12="1159364c952bf676504b627e6b8d4420c1ce7eb2916f0ac8ae50eed7e8ced6f8"
    $a13="1159364c952bf676504b627e6b8d4420c1ce7eb2916f0ac8ae50eed7e8ced6f8"
    $a14="b7170130508f2002460d3e603420011ef75523057e56db8470317e942e388d4d"
    $a15="7655d678c888d13cd130845df4b7e77dfee0c691cabdaf7ee84c268fb43cdacb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_384_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="0bf2c5eed2dc859ca9707ae59a18b5097d580ce705808b80830c5cf5832405073e3fa3491ed7071a2362048edff48295"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="742f12e0aca6501a72089aace68a8eec168b18fda318ba2e87ae0ed5046cb1afa206229a2e871d459359649efb5eec5e"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a8="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a9="bacfa2d2890aed1036ae091a194fbf52c1fe73cbee53cab0a1559feba92b7a2e301df7ba6f8b99d7fc8d537dd4a16864"
    $a10="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a11="ab33c5631e10e1b6039c54c9db2d43be1eaab964066f89ff42201d6528df5cab213d2ab4421c8427e2b5338971af4cd9"
    $a12="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
    $a13="a94a325f944ccdc2cad72d7da27ddd3798f4446da97d85b1dfa7cd465f877d0ce291197c22500a7d278cae7a0fc3f10b"
    $a14="f456f8a04d373f0a4e18faa5b06f6b46ce00d05ac5c1f84e6f69c65da649647ad659bae5b65c7933e106acd5ae669954"
    $a15="ab33c5631e10e1b6039c54c9db2d43be1eaab964066f89ff42201d6528df5cab213d2ab4421c8427e2b5338971af4cd9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule sha3_512_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="d760688da522b4dc3350e6fb68961b0934f911c7d0ff337438cabf4608789ba94ce70b6601d7e08a279ef088716c4b1913b984513fea4c557d404d0598d4f2f1"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="d2082958b8a3adb6763e540bc84cf911872791ca5a08c0fbbfd0b5888516e5ea4bd7298172cea3c269d06fbce8134607a61140cbdb1ee9fa3611a8e5e607393e"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a8="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a9="aa8b49826023eb94e4667e7d5946a77e7c05532e59834ec71088557ec4fab426078adb3023b5dd87f6fb610c883bb10ff8e0e0a2c2d0921f668e00033ecb07ef"
    $a10="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a11="0e1d999fe06b3fb7277ea27201394bbd012aa62e940931a5ec71153f9c9f523b7c5a022a7d9898a7cd10d3d4f5b40efd20e22b24869c568a82d3dbceeb24dea4"
    $a12="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
    $a13="60662fbca9a6677f8a47dc94350fc551e5ce56b055fa3f6d5b23ed19d47e04234c3b61aa5ee7980fba5264345c07e40de95a3552ce610899b96de590d6046d4b"
    $a14="6b69dbfff44c9016c82bc4115674954d12f4077cdc7f7a25231a13e0f46f6cae17e0e4424b09d629935b065667b62c9c7e3b73d98be6ca70863fb7916f5d2f47"
    $a15="0e1d999fe06b3fb7277ea27201394bbd012aa62e940931a5ec71153f9c9f523b7c5a022a7d9898a7cd10d3d4f5b40efd20e22b24869c568a82d3dbceeb24dea4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}

rule base64_hashed_default_creds_sweex
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for sweex. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="MTIzNA=="
    $a2="YWRtaW4="
    $a3="ZXBpY3JvdXRlcg=="
    $a4="===="
    $a5="YWRtaW4="
    $a6="===="
    $a7="===="
    $a8="===="
    $a9="Ymxhbms="
    $a10="===="
    $a11="bXlzd2VleA=="
    $a12="cmRjMTIz"
    $a13="cmRjMTIz"
    $a14="c3dlZXg="
    $a15="bXlzd2VleA=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}


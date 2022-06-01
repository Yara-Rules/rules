/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4fe1b5649b65793fed671ab8e8754681"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="4639225dae97bb4dbc97386aed152a5f"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="4639225dae97bb4dbc97386aed152a5f"
    $a5="4639225dae97bb4dbc97386aed152a5f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a45622dd8c843c09568200b530dbd4ecb60e336c"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="00ff1c17090faf64e6705df7aa93861a24cc1a9f"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="00ff1c17090faf64e6705df7aa93861a24cc1a9f"
    $a5="00ff1c17090faf64e6705df7aa93861a24cc1a9f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8de61672bad5680e61a8ec845d21f45ac3735cfa15056570e5e2405ae431146295fec4798092a21069c65c795d816cf2"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
    $a5="e2b1d58065dd5507a22acf0e6be84e9d6e6cfaab56dd2303cd1e955c2df22a86993e7c8ea941c7a437b58533a8c4a3a8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae11ccee78ea5b4866f46b30b3723c563ba349f59de68b0a3df90059"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="4293831082809645462ed6947c4a90c10a9b531bfc360d409bf49a35"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="4293831082809645462ed6947c4a90c10a9b531bfc360d409bf49a35"
    $a5="4293831082809645462ed6947c4a90c10a9b531bfc360d409bf49a35"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5f92aa629948640346e9fced4967f5bee53194f7dbba0e3d23f538dc3f1954ea9bc038cc43ad11521a2fa029e97da605a2e5612de32415ff6fc6ca2e5cc9f859"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
    $a5="5c69744a9ea50de30fbb41d1cfd41d20c326a6fb5d75df61a18eaf581a694f9f6f86b37ab04a04b1ca2f03aa1fe2236d4892e71d58c30670797cd56da385fd56"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6979df5ffc8f09d7dfcfa6a71b7cd3b955cc9a59f49efcccc818fb08f9c693d3"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="ad6a450bf4435f8f305481804ca478b0ebc73b03c86f5c19acef4b29bee7658a"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="ad6a450bf4435f8f305481804ca478b0ebc73b03c86f5c19acef4b29bee7658a"
    $a5="ad6a450bf4435f8f305481804ca478b0ebc73b03c86f5c19acef4b29bee7658a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="61e6bdc1c26e721e3a9ad98e91eb4ab51a52465604f3106f50ed814bfce42317f635300a6613b30d1355c144748e2b7749c84e43fc42446ce731506a9729aa24"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
    $a5="b74107dc535dbd829045bc54050ec629f9b8f39e8e04e3d267fd93cb06384d5366447caa4808dcc5b258edd1935d4119cc322aab0fbf0f5a4f4bfaee990aa2d4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f22b497b6bd27731340123e3a4445350acc7126e2fba218ac285efb2b5c806d"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
    $a5="90401a1ec1d23d8b1979ee0a1f632186781fdb749ea3f431d3c1bebbbdce7a21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4dae19bd057f83a192b1d2436d69c989b89954ee24a439ad53e98e96"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="aca5858048ee50443cb5ac1d6355f7639741fe5e842027136004a906"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="aca5858048ee50443cb5ac1d6355f7639741fe5e842027136004a906"
    $a5="aca5858048ee50443cb5ac1d6355f7639741fe5e842027136004a906"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5b5ac85d93305cb1bab9d4922e2ed14b68dee32b0bb6f64972b6ea1ad165cc1e"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
    $a5="05155a9f2e0696cd4a54b7380187698f74bf5799f56c99579c94dfce58ad6f8a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c51e39a244f895c625cfefd88fb97507ed2ed35fe9a6a276004a31d0d3cac45ef440b05cae0f8ad2cdd039e1fbb9e37d"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
    $a5="62b8ff9b82a95fc17205943fa97d28ccecdc90c157df42b72e83ab980ad3ba845c241e3821151139cd5590d936153ed2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e9b37faad4c9bc7e33d0f6d86407dc9c77291c667021fc758f26894c0e8975f7e7a2129a35bec16150d4b060fa6d0f5dde234563e133c8dad4829d8e60b89e09"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
    $a5="15a53dbbfb963a99dc174afd5d0860d072134f35ce9e7c53370cd5d00db50b6ae58dc4cc0473672216f5a04a7670cc021cf707bdec518e1cb15107e25167e1b4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_3m
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for 3m. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Vk9MLTAyMTU="
    $a1="===="
    $a2="dm9saXRpb24="
    $a3="===="
    $a4="dm9saXRpb24="
    $a5="dm9saXRpb24="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ab86a1e1ef70dff97959067b723c5c24"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="a36d6ecf13388e1e5419591c1d0887e9"
    $a4="d992bb8deb721e5a032ce41231fb02cc"
    $a5="d992bb8deb721e5a032ce41231fb02cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b1c1d8736f20db3fb6c1c66bb1455ed43909f0d8"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="9153587bc5c5e201f3e349a581f01fe0143b54c2"
    $a4="774cee9970f812928e97dbec8b46bd184d690dfd"
    $a5="774cee9970f812928e97dbec8b46bd184d690dfd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="81ef3e5006ef1e95116c11f7016342035009c64a0793d511d10eaf47379e018677a5f59bca9aa9b32e10eb23b58b0ca7"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="9a11faa04445c9a632c733ff8787823b563dede908ef16e033e50e35a52861988729944c0560a01e90a0c89d688d77e0"
    $a4="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
    $a5="d3ea14b8ad2c447849fbcf27105f7b943093ca6be70cfa3726f62c9aa68ca6312a6f73c8284ec2904816028787f763e1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="70b71e41cbf31e2a563f087bf250131ac2a870ec65b1d788a8d7b5e7"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="b9bf26ea864b73a48c7c8eedd41822605a9339a064426cdd6485c182"
    $a4="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
    $a5="49b929d8c8d228f6a8d06123c4c5c9abc7dd0b0a98af8c0e3e92ec76"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ba0945246f77fdd27f99e1120cc6211f08ddb27ed32af6cf8113df881ab1c823629ec0d65a9a2a7a06c4527e82d95d70a01b776baef2f3737d158b47bddd545"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="4e03a8c7e7b54608c1aaa1ac78e4e9bbd7e70466e4ea7e629daa6b0571290dec441a60444f6467bdb51291873708ddb9c1d1ac57a37ef4f920fe17794440d96d"
    $a4="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
    $a5="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2744ccd10c7533bd736ad890f9dd5cab2adb27b07d500b9493f29cdc420cb2e0"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="d648266682e89af95d2fd0f4e69e12818b89740e2c780eec89e44ae5892e5932"
    $a4="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
    $a5="fff54f2073829bb9f53e03f1a660ac1b97005b09bcd539d00fdf77b8ab3960ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="adb1d9b76d316e5844327b5967cf3306f6c61f840bd30d7d765d73531c48117176b45d589e85e1d8f118ebc148d3741db293a93aeac8cddaab56db71616731d3"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="e38c657b4febf840cd67451c2a18c40360581064289f2fc07be57b523ecf84fda49ed03d9a9f0d58c6b8b99634fab7ce9a95748a36747351099c2a47066a3f3e"
    $a4="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
    $a5="8ab30378335f158b64a6d5a2865df48c4357c47d192f9dbd908cd79264cfde2b185ce3634d471e3b2e05f524afb6929e91f3d00c10aba2acc17e0e0e767ec8a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d1557d33010e742e2e3109d63de39d72030b8fcd7ba52e63d100fc1dd0d22ce4"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="b04fab18cc1da79a461571efa1db7ebdf0e6d7687e4af47296763a4285e7eefd"
    $a4="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
    $a5="6780561953cbdf18b7ad55ace3bf98a2ea496d5c92472faf15e29c5c0736cfd6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6c7a43163008596a88f2638ca2502b1938bd19f7b36cfa52e091d8a7"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="db8be03ad95b60db24a1b3ab1492a48bc3bbf9f6fcacbe79fc70efcb"
    $a4="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
    $a5="ea97e30a08153a029bbcbc81f26dc49de73ee31dfa70c494acf66233"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9660d4def2cb848a0bc21b54980c886392a30952941783b3820f4f1d39191ec7"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="bcbc31574e376353de7b4fa2a9b895635e8129e6e49d61878076cba39b50dd0f"
    $a4="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
    $a5="a2200db0b1a533ccd99538f6ff63a42f47b192c1392ae8847d46a56a0bc2973b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="83df6a6e8366702435757387caae917f89d98255d3ef1f3f16f50e436c130acba250cf3b750d0376a3c85ec0ff17f60a"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="253901e35798fc58539cd8a8d6558135b00ed1bc708b4e2a53394097a4cb4dc9a28ec019bf5f13dac2811678dd963c34"
    $a4="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
    $a5="725b258768583ec6a2a6a66d6cc95f5d38e9da23a48d2db7d1b18ccbce3572fcbd6e61b5e7f8cb72b009c49dc502227f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="601ffaefb2ca69a6a8031ab34e54184fcb05341d673894847d5d0e7b579c97c86f0dd9cae1af620d42470f2fd92e5cbd674117860b4f81366c76daae6ed378a6"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="9700a92084a378567fcbfc158aa1e53a53d06fc4cf2f2b3f0a08cc0c41412c0a495df571928a75aea875027705a4aa793b0f4f7a0f9e32287e9a5cc2175fc3e7"
    $a4="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
    $a5="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_next
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for next. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWU="
    $a1="===="
    $a2="cm9vdA=="
    $a3="TmVYVA=="
    $a4="c2lnbmE="
    $a5="c2lnbmE="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


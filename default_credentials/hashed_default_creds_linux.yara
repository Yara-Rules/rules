/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2c06e8c3109975c3f139d7551e8b5def"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="c653856466c49bc437fb393f2feb991d"
    $a4="87df2cd1570fd297de238aeee667fe0a"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="de1b2a7baf7850243db71c4abd4e5a39"
    $a7="d41d8cd98f00b204e9800998ecf8427e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4ef65bbe462a1eb58f82de24c75235b73f378625"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="39c701bd53359a96dab5e53d4482cdc87fb93dde"
    $a4="7fd86b25e0992e825dfeddd325c9dc5bc72af38e"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="148627088915c721ccebb4c611b859031037e6ad"
    $a7="da39a3ee5e6b4b0d3255bfef95601890afd80709"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4fde05fb05de6eea1371ba1cead5003965921131dd2f9eb6a793db8df94f5349295529a4be706b2ae552c2b1e7d9dc5c"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="ad00c0cc01da6c6fa9fdd8fd8bc5325b3ab5539f56c6414c40a8ea7d7e9047f6518937c179e27b63d3dca6fb00183ef3"
    $a4="1a6b768ea0cdca3bab4e26443c78c2d8127e6cd901215f3f31be977dcb4c82d11cec9fc800b2b430159d12075439958b"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="2f8392252a2789a7907ba3b0c5e4c194994709c8c91257c5c32411a7a49f8baf8cb501002bf1b99dbfbea5fe1405643d"
    $a7="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69058de85b253067b932c37b28618786070260a83cac6c6038ea6d3e"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="456bec773dac454c826c57159eae4e582fe6ec36922606bdcfbd3154"
    $a4="9006e401cadd5ae9a554aa64883f7e16d05308ddf26dcdbcca198358"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="030bdfd061f1580a564a39e804da92859402eebecbf25a58328703ce"
    $a7="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="78d0c5e7c8aecca69286ceb9cd3b53284476abdfb2367d19f95e2763aca74d92b814a7ee9b1bdcfb1b9baa4b6d97a916c68a15d1bbfceca81134c0502b01fdba"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="65f87d365917be0f5229fdf8dd88b67e1713af6db7f0d0f989cac6cadb97b15f44e818e6779f483d6f82844a1e3715d886c70dfffae685ff05371c80151a3c0a"
    $a4="5fa4ac994a3d61782c0ac9c8dabbf89a0b7851adfa0682f56d5efb7d3945f16dae94feb52cfa6853778b58d9994191ddbc719f988109bf3f294ef4c06d40e540"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="1cba0b7e48be1d68562c29bbf83563274c0fb1bbc0be4e19715114575db33234cef1ac2b733e472a99f14b7936d9e820e88d6ad68e98feddc5beb4bb41726522"
    $a7="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8cd626bd979d05205337b47dc6a80edf6372b902e3dd1d10bc99dc3ecfd38f9e"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="1a9d5c50dc8ab2d72f95f2a6277db8391a603b96deabf43ee98ce840d9c3ea62"
    $a4="3815914799634fbdadf211431b8e372390fa35c0d54ed510993adb5b61525f48"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="538d7d9fe78e7baac47a9fbd6f2c68845ecca72dbdc2b47b4c5a0f5620ab8e93"
    $a7="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4e96c2faffe3d2c66e9a0db7d6d2c3f2cb0e72a391dd5f7b51808ffad4cfe0cb527a5ef3117ebb3046de264f4e43753cd129b456adabefd965a71aa93e65558"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="1ced3652ae3b264666e3b4b5b6e35aaf533967b4f2a7d3f9ccc5b99a34b838cb1c6211a0709adbcfcf7433962de3ff7595d53046d7d3c56084c6bf91f30e356d"
    $a4="2cee7aad80d408f8245a2ebe7e2a63b633952491ecc964a3d53b023b912b00d35b07cf555369f7eb82eb8bad03a8e83e204c3e690ac99de0d885193367f92aba"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="b3c6ff14e26261afee8036031612d814df61e2bfee3e5da749a746e0bf75e8314afa744f3cb9f62564a467da846bb5c40b43ce749fe5f5500bdf71ada67f46e0"
    $a7="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="535bcc844713c8cc05d39b9f4493027bd8bd7f69277bcadbd32d0d6a402163ab"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="bfddf7215cd579057074335a0f9736e63b9a19086ea538fca61b7371c11f10a0"
    $a4="77da84470153215f340be062aaa1df6426f1483e615002e5279a23351018ad2a"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="4b3b5ab4b114c99e1021b017929bd936d933815e2d5657d3ef701428c8a8a6dc"
    $a7="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dd5013fb71b711be7ea9893c3ac15e66037d0bcd5d608afd9c3bf91d"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="8c001ea6e7940d0ac41527a40fed5fe6797080b5711cdfca3e2acc63"
    $a4="d0d7d8255681cb0fa80adf9ed3ff73ead34fed4373b1646ea7312faa"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="6eb7e0f3e28725f6b41d46b060b1702bc2b6892d3f15b420888e27f6"
    $a7="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b22d3917a1960954bb2ac983c48e3401a68d06c401de47a8087d95d421843fdb"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="a9bea4999113c04c6c2aea24d8ecb346d0aaae10ca112224418c0e577d41f72b"
    $a4="04d2daa29decf29f76a6e8cdb46dc5e5219dfcd211848b10394a956d7de6fe9a"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="118dbbc0b0c894e13fcc9954c486136ac96d2df3828038e99728c1de2a8eedea"
    $a7="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6defb77a521f98091ffa7680b37075e879213ae16d94267752956efa5a4c6b6c000fcd8bb04a739672c6e373e5ec3019"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="781ed307393d8b070e804898d772f39e184a386dce8ad71ad5971d9ab669ba81b1d4b4fe5a21acecb7306407c4d683c1"
    $a4="b6b758282087c91721a9db96ad7f910e2d3e21ab6093989e044c25e3f2455a4a1358336c0f5ac16422896047ce3cb65d"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="efc17e82f6e0f4303b1235306649a02b19a6e3ff4e223e42fd80eb24c33aec2236ad01857ba174e0cfb17c2461e1ac6c"
    $a7="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="96d251efb3b097ddbb2cb66fe35361fc616f23d2dd7e7408aa5dc852def1b6c5db829426333c159c202185001ee424b538ec00106308c82d1cc59564e74db37b"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="319ef1578057e6710f2dc79d915a14fce3c976c22f2147f2adc612c270df8f207b9cee069e8a85e0ed21179a810f2c02030d21f9812de1d87464deaf7df89f99"
    $a4="e5a93b3b459a469237a88bae2b6e1d364e4ea559efedd94c3f4112fab47b0cef5c8041f2e7c424cc8b2e4ae6f750110a6f3bd966407d7626e00e7e5797a2d6c0"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="57a1d3a48e54d0c51f1e4c7ae3c2c7828d8fcf4304b0135d52d9854ea687c0a071c9432b846bcc2132359def709ae9af3220a5d288bc0cc4ae337d2f05e6014e"
    $a7="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_linux
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for linux. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Z29uem8="
    $a1="===="
    $a2="cm9vdA=="
    $a3="dUNsaW51eA=="
    $a4="c2F0YW4="
    $a5="===="
    $a6="c25ha2U="
    $a7="===="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}


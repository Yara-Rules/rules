/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="d60cadf1a41c651e1f0ade50136bad43"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="383c05bda6f030a44990d354b24f3338"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="d4927dda05af693bff7dfd4c7b40eafb0ef92a78"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="deb4a070484561a680d09eb5976b1ac8a1f932e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="4eafceea1f74f06972fb4d6e39af134b8b209378d24fa1633f792c17f5338f163e2ad752da29c2709f7e224b1f461b9c"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="86eb70004bfe689fca7dee969aa65aceb6904ca3a6bfb90f8de430b6e50746bcaf46841b6e8575c1a82df431b4a83ee0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="2994ba62daf61fa9eb67fa3b597beaa16bd6eaee9d448790e1f3a795"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="fd42bdc3ca2620931aef6b30bce5b093f5e7d1d62d910147cd1469d9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="3f78b24ef73cc8180982787d6db8ade488fa91dbbab294e4fd747a5e0d05c770263589ae093a8c54e71ed13f84f583c37ad9fe232047f20c9e0780fbfcb99056"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="2b0192b720214cb5b5b141a7a152c521cf73cc09fdc8de34f5e8cd0f8bb46e9bb89b739cae2c994a0a87ef03f90e9ccbab86accb5ebf113b9c41f260549803a2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="8950abfda7b727630760dd35bcf5c3daa7631aff223a90f7728c0d2521dde10c"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="37616f647849dcdd7d8efd151bdeeee42f091667a6d75e962fa37379908120a3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="63d6c6d8f0099b183178ab33f559d68eea46181743154d10c7f2a002c49def5301aab271912c9fd1e0b1374787d86d02fe899631444d30194048d8732120bf52"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="b0f0d0645727570b1c1037c67363ed8fef3627bd75701597b0bc24e1bcc75cee1b4c08a7d20853dc48b408366338ceb203d80a4fdbce0179b44594576983f967"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="2fe55b7394a18473a69ee1d9c9f20e5b67b14d285b744b8b867929646085be19"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="d986a30caa82ee231534f399795a36583e396a04886ce9e8606bc2e27df27a36"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="b2b9d72906812bccb5d5cefe9b501e4c6655af4705b6f7023c09a083"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="1ec86d12460ea05a3de6ce41baa0b5e15dfa9680309bad47fbc98d49"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="6b2b200907194f3be700a9e906ca43b0c497069970cc158d6814629c8319ce1f"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="2751f794db6b36464036d66f5671f75a47a8fa7076ccd595ac7bcfb447d4bba8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="25cd49ff744c8d5f5491abc5fa33298015386e5e503af609c0d8bc2500e2b1d7af69ee6adc2b64513d6672c4385e412a"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="4202bd2d8d4cb91a33037b96b8512f2f46b35af7bdb8d66899f9e44d8f0b8c09dcc95043b4fae7b627b23c7f0da04cb1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="e4a970cd201386482d37e9cb4a83a179b20b944c581448dd11e6b36e5fc303a001532c19a08b14351e00f120e9dd89f888503a1d37286f66f5d5767d4e85b04a"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="71b69e23845cb2795a5fd572984e79843b974b9cc12176454db8eb3fa6c54a725bf164b1a0e139b6ea637e44bcbfaa5472f37e73f8cb726dbf599045809df89e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_tinys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for tinys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="dGlueQ=="
    $a2="===="
    $a3="VGlueQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


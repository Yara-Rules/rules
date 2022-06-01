/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="294de3557d9d00b3d2d8a1e6aab028cf"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="ff104b2dfab9fe8c0676587292a636d3"
    $a3="ff104b2dfab9fe8c0676587292a636d3"
    $a4="084e0343a0486ff05530df6c705c8bb4"
    $a5="084e0343a0486ff05530df6c705c8bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="7616bb87bd05f6439e3672ba1b2be55d5beb68b3"
    $a3="7616bb87bd05f6439e3672ba1b2be55d5beb68b3"
    $a4="35675e68f4b5af7b995d9205ad0fc43842f16450"
    $a5="35675e68f4b5af7b995d9205ad0fc43842f16450"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7f9d109c4c8b04efd32a69140fbfc75a48e0be4adb2f8aef8798aa549c6ae1c878150333071246b29f52b821aa511e97"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="adb545c1a26865a6849223515fab5965551871330b08a79bab66c0bdc8d33df11791c92dbea55591b55bf4e7e30926f8"
    $a3="adb545c1a26865a6849223515fab5965551871330b08a79bab66c0bdc8d33df11791c92dbea55591b55bf4e7e30926f8"
    $a4="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
    $a5="41b46393b517f1be9e3798fb4961404d9e7acde208b25f44c154360bba29c1f30196f1058fd06d0bc1e12f6f2d6c35fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2ce11767207a153185b411fb5cd2d3cee0c35a954aa59a1511beed1d"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="7895d9a045f4794241b69df3d77db44df5f05c4bc4b24e3b44a12c1c"
    $a3="7895d9a045f4794241b69df3d77db44df5f05c4bc4b24e3b44a12c1c"
    $a4="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
    $a5="5cf371cef0648f2656ddc13b773aa642251267dbd150597506e96c3a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="004faa89a51aec526b9e89bef712c72253f40a929e7f284f5a4c453facc98d6b90e33fa01f950cafa6932e0f18a28ada89548f7248bcc5b3932d227287e63185"
    $a3="004faa89a51aec526b9e89bef712c72253f40a929e7f284f5a4c453facc98d6b90e33fa01f950cafa6932e0f18a28ada89548f7248bcc5b3932d227287e63185"
    $a4="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
    $a5="b0e0ec7fa0a89577c9341c16cff870789221b310a02cc465f464789407f83f377a87a97d635cac2666147a8fb5fd27d56dea3d4ceba1fc7d02f422dda6794e3c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="1f35e175b07fc080eb57fc9db22a3ce477d87bc5447466815f55864d3b6e6586"
    $a3="1f35e175b07fc080eb57fc9db22a3ce477d87bc5447466815f55864d3b6e6586"
    $a4="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
    $a5="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac90bf4db023d0c5a9344ec19a9f3da5cda88de709f402502bd549511a544e22747913c49d5f296cfc98762bae191c6bb3f7f406efc6c246fc8c0e12d0b279a8"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="816c3133386798ff22a70f32ea8e0952869b99faed26aa6df3b180ff140402ec00cae38b14273d278b02343c9450e049be080f0fc72c9920c17c1c792e11acd3"
    $a3="816c3133386798ff22a70f32ea8e0952869b99faed26aa6df3b180ff140402ec00cae38b14273d278b02343c9450e049be080f0fc72c9920c17c1c792e11acd3"
    $a4="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
    $a5="e5a77580c5fe85c3057991d7abbc057bde892736cc02016c70a5728150c3395272ea57b8a8c18d1b45e7b837c3aec0df4447f9d0df1ae27c33ee0296d37a2708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e06f7374ab7dc222d4086d9afc52ba24ddc4ac30018b423a2356ac6eb9fddaff"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a3="238041a05ef5fb96bbffd6c5de66310bbf24d41406a2305189936e935ed91505"
    $a4="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
    $a5="8be05d5d022c93a6aeedae13896fc3e178d621771e35cd18a36a12838b1d502a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="290cebb49aa996b5f19244127e2c0253710bfb405ac5bf89c539e07b"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="bec6a07ce9c9b3e091598e7ba0387cffb0840666125019aba3570d28"
    $a3="bec6a07ce9c9b3e091598e7ba0387cffb0840666125019aba3570d28"
    $a4="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
    $a5="bf3788f6d03f5756d5696b102c6cef34edc6c92ee814f0db87cf977a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="36e7a2865de35667ff62ee2b3c9135f8352a421a710f247ac927ebd11eff4393"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="f7d7743a4f3ccba2cdb10c43509f49a0b400086a4dd195441b48590ecd5136a3"
    $a3="f7d7743a4f3ccba2cdb10c43509f49a0b400086a4dd195441b48590ecd5136a3"
    $a4="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="14452f57c382ec3a99a1dec4f1a8a47a9e5bf0f159383f4bb913cf6130260f405201598865b5c577fcfbe1f9fc4e2843"
    $a3="14452f57c382ec3a99a1dec4f1a8a47a9e5bf0f159383f4bb913cf6130260f405201598865b5c577fcfbe1f9fc4e2843"
    $a4="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
    $a5="c617f0628590601e6d5356010496d04be85fef0b4eade714c87a93ff959d242053c0faeea83220e1ae1e635974023299"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a3="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a4="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a5="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_ftp_ftp
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ftp_ftp. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YW5vbnltb3Vz"
    $a1="===="
    $a2="ZnRw"
    $a3="ZnRw"
    $a4="Z3Vlc3Q="
    $a5="Z3Vlc3Q="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


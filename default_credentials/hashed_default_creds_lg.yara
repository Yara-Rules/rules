/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="697efa94ad1e665c4d0edd4c810db6fb"
    $a2="d41d8cd98f00b204e9800998ecf8427e"
    $a3="a17bf64aeaa61765872c31c975e0c8d7"
    $a4="4f03a3d7d3dffa764d27606ff3773311"
    $a5="2865a5b14e5a70273a7d311bfc150f4f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="1b10fe8c1f2f5c29f78faafa526afd210ded9fb2"
    $a2="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a3="2c5ffe833e09896b0eff1a6a53ed7e1f480ed48d"
    $a4="536874804ccbc5f27e37f391c27034468b046f9f"
    $a5="502b7dfff6fb4dc619b4933e1cb122df34605430"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="e063d31a6d256a31b2d1882a9cfc0ec4de630d4af37b6e8942a5cb1bd18b2af08fc937e773564b559161b670301d9114"
    $a2="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a3="f1720b2a9e2ec7710c1909251d11415b13c28c347ce3076b5c1cdd9c2442d9f5d3c21f16140266c8e38ddf580ac01477"
    $a4="fc5b21c19e5eaa09d9e763854542dafc8ab1b1ed52e40a0affb78657ee6fa42b9e4b6e5086ed56137863931502bf9c82"
    $a5="3cadbd40dbfec142a48179fca2d840187c11d35b9c072d397cddb3f60d6552c168d1dea7176ad026e5fa7c28085b65d5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="3febb630e97a4b8be0b40acbeb4edbd88a1483c57187f0493d7465ec"
    $a2="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a3="c548e9406aa4075201bef7569657e53b95596c395967050aae3fd74a"
    $a4="a0c63e71cfc267a160fe0bbb4440186c36e2463f10c0bc29299780f9"
    $a5="18d564a5770a4a7c0f24b863fece0809bec76436b412d56325d27bd4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="acf4fd04a648ae5754053813e74c37ed875e024caabe9905ccff0441cd18efb969a58089ab4a60a51545f03ebfb94220105a47185a6aeaf108851cfc513cb7f6"
    $a2="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a3="6176f50e7e7ba120da1edfbba37c8b5429440f6a31d7b89a7a476ebe129525ca282b950a580bd66c2a9b9d11823494577fae197170c904f143ef3fa54b388da9"
    $a4="60124a219c7eda2f7311d13ccd46dcd4ed1dbb93af87ea51ac1bd44d8b370b15641a1e27e2b564039cb3a83d2afee86a158569df4ddda4f8456f47b1cfc90407"
    $a5="b0fb174937313389662ff663034a9f2fdf9219e76ec4ea62a36e67042831e4fea9ad1e56d5b3197efb30ed4d373358a7363a5a7ca88ad0ade6ab1fc05704182d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="4dd98590f9dcdcdddaf268f443300ec1f63ddc8fb5a72e7b4bea2c0e4cc57014"
    $a2="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a3="c21c7591c269bd25db04cdca561d2b7a174f0cdf68f78c5db9c45e761b1f5477"
    $a4="4b7bb8c301065be38ebed64ed1e85e4ef6f6a06210b6c29abc5919619819b7c0"
    $a5="f4d25158ccdd82c2579055b0454efd1ed981a9e670d2d8ff9707f1fa8130ad86"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="cddfcc68ad850c35154c6aca1a70c03adef9d253ebeda58b91c3028b3fe44acfac46ebf6d90a80810389b249845137a758dc0ab0e64d0b5a423080b068325b9f"
    $a2="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a3="a47bf198b0474ddabda13661cac4e72f22378c17fdaa84b51e89f6a4c0d3de33a1353c75ef1a2960a4278398e518b19b90ec597dc0beed26d153e71180276fd3"
    $a4="00686e983bba3c46272a9d1f835b9a58675a67097de6bbe6935f7f0ff5a423c96ee397fa946571defcbca4a8ca62acecb5b77e064cc4b742979070e729937576"
    $a5="c386be2bd6b388cac2a360476b91ee1ddb377117cc056041ca0a31261c64dfcd03a248ce1980998b12a4c1b2ff5cb80b9800b5d040cd849e6d2476134deef944"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="6fa71e9650b7541e9e5e75e67a434bc1521551a29ad163adb27b7466e315be95"
    $a2="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a3="dbb45ab878ed00bed5731326160384334da96e1b98450d2020b55540d5d2b798"
    $a4="6e878fefafb16bf6dbafe7971804bed286be1b5818896598f5bb7e066b7ba6cb"
    $a5="c9dff61df16602f1e0844ee93d5b7f86ee732afb201ed0adc07e4fddf9832ace"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="74e9e35306cb170b41b514726cc07b9017456d0800f2fbd5287a20d8"
    $a2="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a3="f95be5e25e72c3e7d17efb165db75acdca3a3da76010446d0d8f3ee3"
    $a4="30f407542b2ee78bef00ae1727f39fce9438e06d0f3bded5469c3dfa"
    $a5="539bee0eb02f7fcc0359f1dfd8d61dde46fcb9e6aa0783d1d1f621c8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="d99cff6dd5fd907def4381b046a27dca74dc887b3c1581e74c16b46543443c46"
    $a2="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a3="0871c8b26ec07065ad873ffefd2e44d2e2cb58f1d80fa11530f376cdbe0d2512"
    $a4="2162c7dc7edbe9abbfb6bbcad04bfc7275be692342962e775f5d17edfbc68a3d"
    $a5="0d1b2d7bc39a36685f8db2b05ac601d97dbd24aad77073ee1197b672588dfb5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="742f12e0aca6501a72089aace68a8eec168b18fda318ba2e87ae0ed5046cb1afa206229a2e871d459359649efb5eec5e"
    $a2="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a3="697eabf1a204ba2a718da16192b0743c4a96fadcdaeab3f865440a0ee430be40607b46fe228f71ee809c3ccb6f26a784"
    $a4="4656d9acecfccdf88529f64ff58fb9b2acd4ad0552c2aab17518e88727dfde00908e494859469ad9b53b8494a7407b19"
    $a5="fbb99113b6e870d811b63f4b198d80cdbda7534c4cea93e471bfdc6b511faac4a6337280a2bff221d2762802e601bcd5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="d2082958b8a3adb6763e540bc84cf911872791ca5a08c0fbbfd0b5888516e5ea4bd7298172cea3c269d06fbce8134607a61140cbdb1ee9fa3611a8e5e607393e"
    $a2="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a3="15626806c5c0f6aa8daeec89f10051768cdbaf5f8a93923fba238e22ac4712ebd9af66dc9cca1408e86965599fc52d0bd66b791d186690d08faf8a6483043f34"
    $a4="777daf5f51eddb0cae81fe6d350616b98e968b4e6912cd2e08e54ed51cb2289ae3ff99dd31831e81ce1e1ffdb72bb71424908c6c7f3d82119fdc3c993364bdf6"
    $a5="fb7047df9f95750370f85fac8e5dd999d472f80a6a9607366bc57b29ff709726c19b1729a9bd803188ae2b337370fbac165d32e789978784a12ce56e1666548e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_lg
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lg. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="ZXBpY3JvdXRlcg=="
    $a2="===="
    $a3="amFubmll"
    $a4="dmlrcmFt"
    $a5="c2luZ2g="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d41d8cd98f00b204e9800998ecf8427e"
    $a1="b640a0ce465fa2a4150c36b305c1c11b"
    $a2="70682896e24287b0476eff2a14c148f0"
    $a3="a5e7b62d2a96d3dc0067f6fd720f6595"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a1="f11a107f38328604e9320754224b60375758bca1"
    $a2="3f282fcba8933e03a65a6dc92a27de8396961e2f"
    $a3="956c8a9c5dce43c1901f60bd6f87ff00dcb3ded5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a1="ca159b9b56f1690532f9798b083c8b30486e0b27a43a497043138113eb81decd4660a83b41c20e23bcac3a5ae59aee66"
    $a2="e36acd1ea702a6d1ad8778fd8bac520654e687acb68c19c6b4520d984fd67416abdefc6a2ef6535184e4a29381b9a7dd"
    $a3="4f93d97d9272a03709b2ce929322f0b40454b250429fb2fb3915b2af17c5385008c4aba82acc81e2223348fa7d3dc224"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a1="7ebe0c1f8d46c4548f8c0d4ecc050f8fbb9c46406fdbb38e7849134c"
    $a2="879f72dd8c12cb2e03273925d27d23a21354668e9917048b17fbcb7b"
    $a3="80b7bfbafd6f1e45393c72bc0351c9a6fc8258c02d559ce24b37656f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a1="b894dd847286b6b521ccf7fc3300736b5f1daa7115aac2e2ae2704e26cb882af2264fccd5df99fc312fba6b9b49815edadfbff4f70253ca7d8da9e2535960e77"
    $a2="38b6664d0f52faf6020a6959f21ccc36c03d322f61cc6e23d644b6fe5444551c59bf2610ff6acf12a517d2ae18d53db088ec3774bc75cfbc677ca8b5f9ae2fd2"
    $a3="31d76799e3d86137c1b9554ba3252bcfeaf44496e84bd251a97e909e07aff3b1fa91c7deb7dfd3c6534c1b4c790d18949c742da853165bf7e2c7c15abe1f85fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a1="5a638a128ca67348f1073ba0aed26d85905a29128cbd71b250c9cf4e598c7f0d"
    $a2="181229424893bb65d94a74c2132b8b9e5adfe851464fdb5cb9f49e8a8204be7b"
    $a3="45f28ade5d260ab2977678024df5c1b01e6ac2b3b576a99280f45a3e31e3761c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a1="3939d9f5686d15132b1d0c63a941064b5e4ecd9a4e7aea0b7dd491bf44f614e29a82590116be7da687065564b833f9f9c865e874437813ea0129c2cd834c0da3"
    $a2="bdc242cf50e30b58e26c2d8167cd1c3a3cc9b6caf11d44767e77f3f74bad3ab9dbbd2b8ab496ee34ccca381db17c80dd30b38701fdf2e3ebb106afcabc85e260"
    $a3="a14280a57284b16718c10ba0a699ab2b30c2d32b3dbff62d08c31627c1ec61b6d81d12a6c21806b1e47718af7321bd7d7019d96b8e5f55ec7ab5a7db1b8dbe6f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a1="653388c366370e27d96296e86bb56631f22568ab0ddc74cd479ac8508b786832"
    $a2="4c2888149c828966f2116ca786c6b7088806f0d5537944f296afc83330bcfd32"
    $a3="c88ee87733fb0e80e02fea1ebb1c247eb24b852d918c8d10f5f0996c37f5c1a2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a1="a02733575ec767bfdb332a02357d0184c1766df0041edf18ff7740ae"
    $a2="43fd042a7b13132449c9d8b23c040c2fe030b8447df1781b30cf70a2"
    $a3="af27bab819ef5d6366fe52acd4f03a692e11f055d00194f89ff777d3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a1="386b98c35da7acd8230e74499ea778999035166f7031761b52bed1bd299cfb85"
    $a2="03789d1aa662b7e4e363b211f026f6d840912607b7ccdbb5210322d378ce1f4d"
    $a3="890da150f32d2db6fc8f1254b1671cec94e3114a453cb98ef67ec942ee744367"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a1="dd23fabea5d845ada38cc52d0485d00f982c35dfc90717c6f9777943e285151168adbbc730773af5ee908d17799c5087"
    $a2="1bc849b02bffdc35def1bc15ff5d80246a34cc2f4ace9baacfbae2888c8f5abdc797b5a46b99dea75b34680cfbeae169"
    $a3="c55252fb45db32e4e921369d697a018eb47d8f11c98b3bc6889fcdc3818557d3c18469bddf61364e06b05b4524a67130"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a1="ea12f04bb7cd09086258d88763da3554eecf9325c51d75caf4576105d34d9a8c3311ced9a2c6e10b56611a5ed8ce663198ecc2beaa85a673a1a40ff3a40f9fbe"
    $a2="9dde8fdbe67cea1d807f4185e8938ec259b2f1b1cfe45149f023476fcedb4badd97241109ef77130cc4048fed73129e3cf8404a728b2a41bcbc47be8215fa8a3"
    $a3="ea25d8aa99547f51d39d88f61528ad06f3d633d73adc03f5a5e4552a5fd4fd67a084644d4983b503632048c508f02909d6c0fd757e37431743a0a8a130452f74"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_fujitsu_siemens
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for fujitsu_siemens. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="===="
    $a1="Y29ubmVjdA=="
    $a2="bWFuYWdl"
    $a3="IW1hbmFnZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


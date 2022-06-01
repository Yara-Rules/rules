/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="21232f297a57a5a743894a0e4a801fc3"
    $a3="2097d7b063d6f8b5cc803abf3df758aa"
    $a4="d41d8cd98f00b204e9800998ecf8427e"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
    $a6="9549dd6065d019211460c59a86dd6536"
    $a7="708d22a444cbcff0612ce71170678f6f"
    $a8="5993428babd2cb253834e06de1800916"
    $a9="5993428babd2cb253834e06de1800916"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a3="6d8cd824e9c86f9c1c4252cb2dfd33dc2f57e894"
    $a4="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a6="7b202d57f214af016fe2923be40110740dd5bb91"
    $a7="01da782062ecbbbfb02faa80f4af6f3e683d14df"
    $a8="72667073ecd92c5757240bb2c034538615b03cd0"
    $a9="72667073ecd92c5757240bb2c034538615b03cd0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a3="64eec76b124335a27abdf2cd9fc3fb766ee95eadd8d119cc9a78e9c00bbb159a8c2b547d9dfb5ab8cadd7fa83a5193f3"
    $a4="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a6="a35e580c5e221b1031137ad24f272e05cceb72d5f7f6821320e7ba0a883154491948600073e063ef9d89a91887775aa2"
    $a7="7a703a46191390ef278132e58468f0776653d03018f57772adee470fd9f8284e703bc20b988d54abd46d6865323d3feb"
    $a8="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
    $a9="4b3e1edc3b1184afb902e4a1afe7280a2512740d2cb4a2a0e8bca2f94f2fc46f00bc536a99f5576082a83b19e8548f89"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a3="a344a7a157fe55175b70cb5a6867b11b680aeb6e20f8f84b988b2897"
    $a4="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a6="aaa4bcff925fb93b9014e8d9f80453e7f9eed710d986541b176677c0"
    $a7="d21f1da65a8fb4b705dd926314f17f705f3d5c9208b840d191052e99"
    $a8="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
    $a9="2a36636a9c970899bcacb080e63ad12da7996344d24b54e61eb7e26e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a3="4388d32f5d77a84bcea8f3502135bf79bc21deb1fa669e00775cc083a50d15fe3c47dc242f6712f24c831b73426fe7b49ffe032d59663859813f41318008c3d6"
    $a4="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a6="b9d3bbccda0a4d0637df4e086a9f2e73f7a8e0eda030f75cc7d499b2907b1da15220b2a5784daec741c37ab5e3f97eab3ae5e091427f68d272060a8479278423"
    $a7="6e8e257ac27e865dd3d7d28ad42b8940e24693729c2191be9f6410cbbc9f3846f77242b01ce681a7c05c5417fc8373061bfe93a5e50c164d81ba2aeee24a6a2e"
    $a8="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
    $a9="371da7b035a29070b0ee37c16db51d32af6470d9a201fc80070c7fca6d2264c847fdd3f323a971622c5efffe890f3bf72ba2b1816347522b5b1375ec97b64e33"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="f1f5175cac7219d5274210b1b36acd6e2693a84fe41be92d5810cca2dd7104ff"
    $a4="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a6="06c8aaa93d80a768829b6005973fa92e34612849b79910c8be8e3b006cf91c61"
    $a7="2333b56c0cdcb88e5ae5bb9410ef769e5b60a313f03762ad0e1258f0e9abfdfd"
    $a8="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
    $a9="8547b7d11af8a0ddb560ae8e25021ae1c04e299ed3145dddd86a1ed053a6c159"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a3="22b0dae0bc77d7551a5422bfe873dac6a40ecd29b1681b661a31ac42a2009809327c80e4c9e1cea735858a744450835dca72a02353857b9a1f008e03253c0dae"
    $a4="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a6="22261d10bcffd6738bf1bd49af3e89c5735657430117fe58280df017b2c4b1970f52c94fbb44ca02d82c95c92f26e54cd8e7be5b6051ca491db604a2c9f31135"
    $a7="d77b59c8171239b6311b2fef70bbd72dbd8562868fb0e97b236b38dd549d49bab7c2623f67e51a4585c2170600b055617bf681b9ffd1133896008eb4e7940c0f"
    $a8="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
    $a9="d12452ae660aedd5848621b81314abbc6db8b10a5ff5918e9aed1321e5dffbd8ffbd3a7e71e83ab5c3fb25f58a3b3b89517cfc165418d758f6f8cc09d42810a7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a3="51159e4877dd0c189bfccb3c8a4fa991fac8a766435d522d82f04d01341b7a7b"
    $a4="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a6="e5509bb5cc9c58b36ac26478cdb1bd131ecffaad0e05aa871518f6d249161d90"
    $a7="f0bf5ec0522430f0673e8d9288862c68c5646560e616b5caa73c53ced4fb3a59"
    $a8="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
    $a9="d1d90a972e12df922d9019c07d2ff7c767b8c1a5f0b7f4c7eafd9de4da954b9b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="9baed77c2d840f9d027c100f1f09735d55086271731a4344add77298"
    $a4="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a6="09dce0ca05c368202e5478365e75ab15c529903416808e8a61bbb542"
    $a7="d699b39c4271583859534814ab9bd96e09fb0962c639171691cca3c1"
    $a8="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
    $a9="790e62018c699bfdb1d4df6e2264a7ae469d6c9f5e563745250d6055"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a3="382eb1cdd10deb82263887f746b3b5d52070073fe9e598aca2432874270c56ae"
    $a4="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a6="d46b2ac485394ab8ef0a0f0fd4fe1cf11188dac9fc6fb4672f79cf9ca3f6385e"
    $a7="08dbd49dbe3dce242f72437b2d4cd1443e3e51844a87579775a6d8566fbb61fb"
    $a8="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
    $a9="981c96a9a479cc7f3353cddf89d90e04fdf10993fb43293c17b06359242ef8cb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="734336f2919c992320b8b4a2296e3619af30a1a33c99fd223af5e32611d6e5a844bfb33e23af8f7f9ae8d4894d90322b"
    $a4="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a6="713c7fcf2680a4f564d9a03a7f0d7ba60f16c9e9012ffc1bd1e5ed4ef6b6d4bb32e38edafaf0b7d315766b3a971ba18a"
    $a7="53883849b9ac0244fec1608bf7c8332604b29c069c9e62c142b0cb2cf8a361f8fc44d1583538e39771ebbb3178d8b199"
    $a8="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
    $a9="c23021929ae92423cb46e50de33070cd268fa336ce2682a81cdcb02f97c2a1997efb8168393d90dbd6f4778d3da7c524"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a3="66a646f62cf6febbf71c02724d0019e878e44f06de95233dff368d6c241322ac57268597f79542486ac5757876f77722e73698bf7ffb29fdf2f3717b8c67dd9f"
    $a4="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a6="ad0c9f9157129a815aa678c8464c440984c1ff2751ad4fe751af01b647e4213e75e8f1a9bc1a3b04bb5b97ba20617754131ff8accac33ff822a7fb05e92410df"
    $a7="5334811cfcbf126ba085c5699fdbf9b71afcc67b529a8f073e2f7e82204ec1fae8f7969f0acbaa45f67ad4f8a519f5d9eedd472ca43602eda8e9dbc890e5b2a8"
    $a8="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
    $a9="d477031231112e4e5328469d4af80d8771c394026160f82fb47c281bd877c1b9a19757081e3cbd68b3ffd86f32edad1f5076eda087e9bd7fc91317fb0fc94063"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_netopia
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netopia. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="===="
    $a2="YWRtaW4="
    $a3="bm93YXk="
    $a4="===="
    $a5="===="
    $a6="ZmFjdG9yeQ=="
    $a7="KHNlZSBub3RlKQ=="
    $a8="bmV0b3BpYQ=="
    $a9="bmV0b3BpYQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}


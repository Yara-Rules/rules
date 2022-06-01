/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7b7bc2512ee1fedcd76bdc68926d4f7b"
    $a1="aa1d78f3088c0dbba0f00edae73c01fb"
    $a2="0dd439cf8f77110908a897d1aadfcd86"
    $a3="0352a4836f051450594c4d68277a3529"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a1="60f39b672c37678733c0751ba95a7d4459a4fa26"
    $a2="f69e7426b2f473178b7f09b04539ec49337fd723"
    $a3="9bd11ca220d0747adbf182a536c24a12790c36a8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb5d13481d7585712e60785bb95b43ce5a00a4c6380ce30785be8b69c0ab257195d89b9606b266ba5774c5e5ef045a10"
    $a1="75e04979409f1a890cd878cc917327a7bd482d7a31db27c8e7dce0d405acd04420427daa6fbc5a5df78eb7ccda04a62b"
    $a2="3d9fe3fac33df0a8060204598edf4b25dcdaf8c28581bd7a11b5220ce26b44686ff58c02318385fb1e2842ad113e13aa"
    $a3="4d361ba1f1b7d16b6c92cb212b54754b8bfaefd426790738d42c58dc1e8ac24a9ec915444e5e2bbdd379bcb348d1e0e3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6f4a35b825e20e94b581661916d82a96d4259b95cdf26f5dc3dec913"
    $a1="4393b0565dec4c736e2fde4af97d30ac7641aaee91faaa80de5cff94"
    $a2="4811d616cf90067443cd4c72fe3ef6d1d8c1ee7433f4bb4582232412"
    $a3="be03e9c01bbd5f83c9abd946ad4a156bf8d8d45519fd1337f8a1a87f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="df09aec85d056853f2d9da9c8627db3507f39820594efe303980ac45339f80e2e1430f0f7e639635e7f6b12d185367a3938eaa7b0f2f84cbd857a7375617affc"
    $a1="cf6971a43cd56a6ef8a0a0be1bc3f0c98ad1a32cffcf9a6e741424cb214b94e239f58303df5a808949114993b41cabff5f30d75cf6e4dfa8970df40b34d73b40"
    $a2="a31b8f4074f0695d0f1df345fb854c1d149fe7043455f3e12ee00d2b3b2c31f849769f04f843edb52739ed070ead98eec6ae56cbe9cb611aba101742db21b61f"
    $a3="28fecdbd0fe2a78f281159f5fc18ed7ba1c6786da6f2007842c27f39f6927066a45962a16dee7dc61532ec2a8bce55a2855d143c4fcb2503075e8ebe2407275f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7d3e769f3f593dadcb8634cc5b09fc90dd3a61c4a06a79cb0923662fe6fae6b"
    $a1="7208a9649eaba97136a9f3622af20bd4db6bcc6e18e50df2aa60d126e78b2a80"
    $a2="65f2c6d4f0b55dfd3e7555b7dfe740273a1a162e3647ac9afbd8dcf3bf745146"
    $a3="fe88d15496bb764bb68e7c2cc2d7626594194b4a59b45b721d58dcdefcd2d5ad"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="715f92db3d0bb9b61f5d9e600203a54868f6e57d007ef72b02ddfcb1f35959dd8b90100815818584bbae097249f52fb298b5de87f3487ec010d793e1448c8838"
    $a1="f63ecf15e5394752b769f5a96edb5f14fd8c5a48cb6a1582556a5db146e82ceff6efd16c5b50f1db3e38a7d2825bc90b67b309908227bc2a7de90059579314ff"
    $a2="91e3de309f10ae1c579417f9607b3d4f2d7910871a5328b162d0dbe82a076b6253f6e88ddb50ab7b4f7e2b133af58a0b7ca522654a0e07ac207862170916556b"
    $a3="4b1ef8a2a4246b08c89a7fac3b8f5cd0678cdd982abb4238b9585c8c7864508dad8839324af2951c693baaed1f5afe55e3dbe07d02a05a190dbb81a1c952e58d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="24b5bbb10338d280366de1bbbe705e639f239c1ec6fb291b27c96c7e9a75d176"
    $a1="47f17c90713a26870661f3a7db598dd6ed834bad229a5d77c2d337ce2c41d2c9"
    $a2="7062dbecf4252422905bbd339a24447612d9f5b7d9aa7338f30511eb943cdd4e"
    $a3="b4555021bf8e26dbe3a2c2dacdd0d4295e3f765a577cd17e7f6d146587d4ed5c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a1="7d3a5480e48af890f8480168a5ab4c9bfda130686b4f9c773de3b120"
    $a2="823d5428f2e78f4e178af81b6aff297103a8491d0326960efe930fdb"
    $a3="4ef56d89c836b63396d348184cc3cc5b2c74fcd0303dd25d6c3d9c1c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a1="a7c122f023a9592064eeaf29aaef9386bc49cabf221eaeeab657fda12260b125"
    $a2="4660630aa2718174e349ac368b7667d0568ba8286106dfec7edcdff7f2769a15"
    $a3="035ea5e12cb4a59f4923d04f5782cd9b5404856c22cec75f1e98099e47c4a8fb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a1="be15acb7f4f0a146e35635403b0a0343f84aa3a914921e5e063dc348555f7b4c28cc6cb77138d4fc91658b049d0ad3a6"
    $a2="66569c23c6673c6680f54058fe977f85aa13db77beeba4908aa343467ef0a1e18377f17a137b692fc625d503f8347754"
    $a3="a969b7ebb7d36c724aea58110580053fdff1169bad7bbeca009bf014ced6f73665d92c85cff519dfcf106c887b1e4948"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a1="665cac670e4a335a7b818049cb1cd1d9540edf9549bb94a3b29eb38654a29561cc7bbe95d1bfeffbdc67e1e9f66fdc128f6f731e6862e7c3716b2cf160984b52"
    $a2="46b6831de3414a349e105ac67c83e896716b765a044519121a08062ddf3ec86ff6b11e9c9ac697d0e515a3aba4346307793211a3127c5c1410ec2cd771d62943"
    $a3="c52ea1cda8ad0e4b59fd94bc59e6f6dfc8c47db398a65fc814f8283fc71ac2cae9272aeef62150a4f748761272e92ed644228bc124811ec6b4a8cb7f24c33a56"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_bmc_software
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bmc_software. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWRtaW5pc3RyYXRvcg=="
    $a1="dGhlIHNhbWUgYWxsIG92ZXI="
    $a2="QmVzdDFfVXNlcg=="
    $a3="QmFja3VwVSRy"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


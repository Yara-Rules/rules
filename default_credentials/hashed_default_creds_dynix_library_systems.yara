/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fce458da5814089639960610c48d19d2"
    $a1="d41d8cd98f00b204e9800998ecf8427e"
    $a2="cb0a59495dfabbf78b33afa5ea3aa341"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
    $a4="ddbb81a9e3aab6cfa19ad8eb2389efd4"
    $a5="d41d8cd98f00b204e9800998ecf8427e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="56927bd4b63d1139d038e026131e35037288491b"
    $a1="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a2="7b8a89cea4fb5ddaff8275b4db86ede69c828fa4"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
    $a4="93d5cdf0fbce4ae8d70e72b5109a926e1641df8a"
    $a5="da39a3ee5e6b4b0d3255bfef95601890afd80709"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58893a8cd12139027876c17330028578b3f636d206991274a32bb327e0d60f240059178925803bb99d67a6ffa995e2d5"
    $a1="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a2="dca7cb469eb06a70d0ca90c4abd8abb68fa48eadf3395f80239377f3038b406293b58182206ea7a3f1f987245f5bf754"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    $a4="31734a748efb865678e60cff79e83ca05a838698b3473c1737f2df002e313377d08aa360a1bf0045558b0ed6205a7fa7"
    $a5="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="391225742fe3bf8f2bdfe217ef8dbbc6129a294e24a0cc4721f41236"
    $a1="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a2="af6d1370524e80f61d29a5be1583c0b040a63fae2bddbe4b41b40984"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    $a4="68ae95e1d04198c9b6bb48401945c529c3a58b089fa6df3ebcf05415"
    $a5="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2392ca368aa5fcaa088a18d3a3098f746cfcfe100f6af7d1ccb7ef1ef04f4d1458d5de5a1798c18d5513b64f824d3c4e986cd5ec4591a7bdc55dfd6fbab57645"
    $a1="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a2="0a2231bd683ab3c1a6b29873f23f20a6518bf5217f782abe2bcc425198c484f5377cbfc5f22504554990bea89cd45e488308bcd7b070345501e5f366f7cc546c"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    $a4="1610c54e97170a56f2a3d33e572458123d6ba7d377fe3f206637c21c96ca3a9ee46c4156e2c52a712855ee0fa10e994d665cf98b530c7ca64eb047d3c4b7e482"
    $a5="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a42f62edb77e8f3021dc52f45993e0eab397c1f7e6b0b4474c64e5b328aa531"
    $a1="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a2="d77982267d9699c2a57bcab5bb975a1935f6427002f52fd4569762fd72db3a94"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    $a4="7175b03373a21422fff5bffa408eeae8728d45675bb3a66635b00737ebbacc6d"
    $a5="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc1e510c467c4f33453ac10e524088c3b038d394176c7ca467b5727994209224cb275dee50aed65923a5fedcabb12850e9d2a7fb1c2a749bc60f7749e662a996"
    $a1="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a2="f4092a04a26c17a7cbb249b85801226f8e8f88efda3d3f03f72f69ca091dc21b2170b17ed44771ffaaa2cb9d70c3de6d5fafcf2fa125298f5ceaa7b1cfaa1601"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    $a4="f71592abf9f9a90f1fb41a1013f76f1c49edabe306541b3681f498d3750ff275fd2e87950e5ed2d9cc2290a9dc8dbf20d25c47b58c34c7aa08d9c6d6522351c2"
    $a5="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ecdef271f859bbb4638c8400c9d3fb451dafcaa800a31de77a960151806603f0"
    $a1="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a2="de9d7bf5b98354f8ef3933a60e4e7b09b5668af9ad52b1a895b0a580f7b22b73"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
    $a4="f0a31472b4cebc631185ef89a0cde008953cdb0890a945433fadcc63f68c3db2"
    $a5="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="358cc3394306756dc833eef35fd4240819bea6ce10fd394141b3a8b3"
    $a1="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a2="16a9ae29e3dff188cab3de1b98fa49b7ee3718a049a3cead0f562e80"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    $a4="a3ccfb44e0bb2a70452e456359cad3b3a2e70074f1fd684fd107e61a"
    $a5="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3f23c4fee1b9a39509c69c596a66895b37ce7ceacbf962ed5b698a8956878378"
    $a1="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a2="8f408f8d9b030b31b154a8399f66523242045f7878a3268fc4008ef927e0e993"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    $a4="48711b499dfe17b61b2656470b05ac51599db28a8b4a71ff6d9a3132ff6f6d46"
    $a5="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1111f32e3098f2e956063e3a92e75d0dae1be2a9478ae03e955bce997e1ef55a08dfe441c6c83fe74ea16404acd2201e"
    $a1="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a2="5c03fc80b63f2075102e75efb771f750ae22c5866397aafc3d8dda9019615aec2c341f1a4fec061e8433e25eda850c3d"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    $a4="617c00fec5b2d512ae93cd15681b61136d811820370647d014f1a637d7dbb20b377df569018541f3f8c33d3da3445d73"
    $a5="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a9491361672ca81aa0a83bc47b0f5de61df977bfec2231c1c1aef4a0134d1c41399ab69eff2a64099062ee805a7706a1343a005afff03597bc4037927fb13833"
    $a1="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a2="50e04adc1cce91b09070044e09bf3a0f25c189599e2f1d4c036944a71f974a042f1290d9f2cd4b9a5ce45423deef176944a0635d0ea55ba8625520633d198260"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    $a4="270c3452df01cada0d44980caec9ddfc28d63dd1f9d2b8742ab224b153e682d267e51d40dd93e46528724a592c589c7d4fcfa9dbacb73ac082a984643bb35bbc"
    $a5="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_dynix_library_systems
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for dynix_library_systems. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2lyYw=="
    $a1="===="
    $a2="TElCUkFSWQ=="
    $a3="===="
    $a4="U0VUVVA="
    $a5="===="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


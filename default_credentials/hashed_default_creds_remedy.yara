/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="828756e625ff179da5ff2f484e310156"
    $a1="b48636545e7f99c438575eba2bf54b5b"
    $a2="f0258b6685684c113bad94d91b8fa02a"
    $a3="d41d8cd98f00b204e9800998ecf8427e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="473d4a427f3fe68021a4de53f65854cacf2039bc"
    $a1="54cbe24bc0f34e350c5b49b49762a02f310122f6"
    $a2="e52c854d5631eec7468ba4727b4c77eb745f2965"
    $a3="da39a3ee5e6b4b0d3255bfef95601890afd80709"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6578b5e0b2b7765deee809fdcdb776cc1887958830aad0894e76b62d56c1872a39252877cde9d8964fa8e00c446843c"
    $a1="99e25df9a9df23daf6c88b3d6026b406b0317189bc7b46d017aae3d9ea3f934747ed17c1b19d25b81cf75ccef57af520"
    $a2="5c1488428584f373fe5de7089ac4dc2d6af42bcc038f9876918ae33b4c3c0678e5a9b90bfb05947722b3637d462666ba"
    $a3="38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed3aa205763faca52666faa7f51e20d013f2f6f7cc4048dc1441d3c5"
    $a1="5ee5ba6fb99f33d399a4cd309e53d985b64dc17ba10b24af85220bb9"
    $a2="edcbf9795847b8a2127aa24594e32fb9e47158bed610a23afb09236f"
    $a3="d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f40435d34eddfbe0f417b8cf3b221ccc6a8cbd95dc46240bc1d6d8d7812efd3448184ce605ebeb621715307f51a017497cb33807306ad340e74d6dc910235f4f"
    $a1="1dfe7eee12f7ce4464aaf82ce5ebc0cce393942642a85dd40af57178479fe39674c06d4ca5bdfc9970396b5c12aa54c088095c7cdf2a8b7bb4b3f0e7e3b01425"
    $a2="4cfbff66f656e328b2b7c593bc198174b1e09b113816040c8f567cc26f03c6abe13ef411f6f5e4c99d7928c23e45ffcb5714aca00bfbc626c8d31ce068dfa8fc"
    $a3="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eeb1de5e38399c53af776369808a9b6b8d73682a51fa39ff1363ba20cb4d5032"
    $a1="4d70230cc4b3c134b818b70ea04e061b80c68515237ea687cf935e0fb2e747c4"
    $a2="8a2cc0673b1c428315fe84c0138d95c3ddda30baf81e7d9aa821f1ca47098193"
    $a3="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9e67456dda5d07395c38c8c8f789d830ab93690b1252c7a9cafbf4ae78853bd759b6f9e6da7a1a9fb8f57b3d49f1c4ffc749863a3871e8112643ef8b62eb095c"
    $a1="32acaf528294e9f37fcb1f1e147a5951e76ade3ee935d9924c228e29a21231b8e30f369a575512f38182d18760509431558a59f9a423f381714997d1b134346f"
    $a2="d0648eadb01154c79b43028fe4f35825d28c13cb0deb390ec754d89c6530c1ed5781844f20d0b133a5507bf08821e815cb69876c93faf003a84e4eadaf9b1031"
    $a3="786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cbdd5921bbd6372236e3d8ffc1990c1bbf2bff8f89b35a3726dfa15c0e47e5ea"
    $a1="7de058acc11640629e1940d47348a03f2db90eb95afff99a824d53b949a7032d"
    $a2="db896e1aec0f06f4ef36f589bdc2e7dc96d4fd0deb51538a90806f6025ae3291"
    $a3="69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a9303751e638eb7e798d1aad0711df288906a1ebca2ef6f856bc741c"
    $a1="c91f674025e3bb73a507f7d6ca9c739408d531d738cc7a16fbcc9854"
    $a2="584329b667261e773acb3f183233dd682c225a0a9bdc551e0f10da8e"
    $a3="6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="abafb3efd43be953e6651a13dc797d09e799e68fc6172983374d38ca47b4e4d8"
    $a1="a871cd4e7a17d4d7e77ae38f8b7d82c0b4857cf0b6e3647bc9f498f4fb191571"
    $a2="ddad25fb24bd67c0ad883ac9c747943036ec068837c8a894e44f29244548f4ed"
    $a3="a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c41d308c572bc2aa6574a9fd8dc7fe268550ddeeb4e049b8508f6780198c13284f32b3a0cb1f91b44d6ab0eef22f4bce"
    $a1="2dbc678d2b0ef9060ed75187c0f8262ac6111382096bd247571f75329d8c4da88aa75213d47794386ae2b4d0b64907ae"
    $a2="34fffde42c88523308447aa4af6b10f6ef258ab6e15a0a4c364fcb40b1f980febdf801a72ccd980fd2669ad4f40396be"
    $a3="0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21615caf63a7252caecd365b3e538fb27a66bf184a1d0f79e2081eea0e03d5ab3b1e232e8d8295bd7aa06cfd295900f65004c55dc9e37a7a56c812293dd78fb6"
    $a1="ef7e5953feeb9588e6916882e26695aff6cea2f442556bc25bc6603a95fc5efc1e58c6573edf215d296ee93a325925f7ee32eb64cfdf274be7670bdfe5d600a4"
    $a2="7201dcc5994fb5d74bc79c39ed7c755924c0d29a71f2ddbc257f35c69f06b4f730b357f71469e7087597e77e9538c300ea5c988dcc57e21a3f93a9a1d466310c"
    $a3="a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_remedy
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for remedy. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QVJBZG1pbg=="
    $a1="QVIjQWRtaW4j"
    $a2="RGVtbw=="
    $a3="===="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


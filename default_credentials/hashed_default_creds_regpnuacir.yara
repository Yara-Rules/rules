/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6d95cbc3f8b0c077adecbc313235b835"
    $a1="d54d1702ad0f8326224b817c796763c9"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68caa942672b1e85124da2a9046c245cd61309c3"
    $a1="b986415c93241513d33d01fcf532a6c47ac4f3ee"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db286047f4506f3b7c2e110b8c0425ece106d769fc0416fc307f2308563a6b510de342840bd0ed18b5a4ce978d8e5bb8"
    $a1="6fdb9c3a439c356436b33762492e8d9a7c2aab1c31f135f1345f71353912b8d7c93321e2dad31941e379ada0fce7d01f"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="773b7e92797eb2f7176cc82ae23d252d971739eb2f029e33abe767e7"
    $a1="16a72b36ce4d3ab7d58f2e11d445bd81725e2960af2160b40d010eab"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac73f333529ff75720ee24f8963653d237a1b34ec2956a1143fed5ca5d4a53ea2c7b40594f2c258a0f34db0d49452d49cf43581e431da691df4abd63aa2e5144"
    $a1="1e53125d5130816a5e6ab3f160ed93d1f498edc3fdacf89ec901c749a09a2d01e1713a3c454f221af5a8069a9fc4829e648a8fe51cd43e35ab4e6c11e8f4bd54"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="485600b958a10477f44c1839f8bd7ce4934a4409be451d258f7cd433e19afb6d"
    $a1="4f9f10b304cfe9b2b11fcb1387f694e18f08ea358c7e9f567434d3ad6cbd7fc4"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8b5d353b7f1f8f96d3ada7a56b92b25d7d98c9e807a802ec537e1f144d3a144fdf088caf039a21d2eca78edcf68b662b1d8d9aef80fec918e458151753dce9d5"
    $a1="40d092076d9173a0d632b4ba20427d832009da5a8edcf65e080f4b790f2466ddd558d2b5a700bbbeec052de30c551bb40bf289c6697d89a091da477df7583ccc"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cf5d9105309f036fd3449ef4fe73905e6833a5f5ed6e84517da6b211404a12c7"
    $a1="de613f8c4e16e20707b811049659a3bfb6de9a154885c4e63bc4cbdebc387bda"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7da6a646362d266261858a7d7f61e3e59d6bb630dc117d291737dbf1"
    $a1="d85a99dc2399dfd78468a881e5813701010e7d89c8b6075893bae08a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad4dda808bc8ebeb2aafe9815bdcc1f176c9a80e2f5d92fc16e444ce8da270d0"
    $a1="7a80f3ff71527ab559be9f18eb4205aeb85ea7896f55534a960e50a018e75322"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f5df22fa097933f4c11acdefaf7eefa936c9dd136cae8cdd4b3fcb1ab85a1657bc106e7460812bcd996c65c57d96594c"
    $a1="833f2b67dc4ca68257c7613202b75cf45439036d2b88f4a7a02ca9430418f3fc8f2fe4e371aa83cda2812ceb51fc9e48"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="08271866e8bf85bb557857824e1a7c837aa3aaa85271337679b629e821ab8139b1d451a8ca904c06dde295741a309634c8a90b456bb1687e2c8c20eb79f2c567"
    $a1="8059160be47a1cf875f097587f340c5c3a91821d78bd2fcce01583313e37806f48f7f47e428a43d0dafdaff454b7d208439a28dae530bcba9c3d9004d61948f6"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_regpnuacir
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for regpnuacir. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ODgwMTc1NDQ1"
    $a1="MTEyMjMzNDQ="
condition:
    ($a0 and $a1)
}


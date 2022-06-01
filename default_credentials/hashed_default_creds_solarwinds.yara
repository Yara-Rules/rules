/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e236393d49fe31275590f4d159cc0f15"
    $a1="1181ffafbb62db1e18936a7443e713aa"
    $a2="4acf954119d5bf8c0ef5ce07f396defb"
    $a3="4acf954119d5bf8c0ef5ce07f396defb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9678e54620f8db82406b94fa0c82b187c136c54a"
    $a1="4395dfa6b49ad83e507268e10cde99a27c76f085"
    $a2="f01d972ce50c9fc9ee69e5feb87aed03a9c70202"
    $a3="f01d972ce50c9fc9ee69e5feb87aed03a9c70202"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1484de0772e0b53151ead333a852c1a103f89583de67f68f12ca6190e6c063a093e6a4ea33f99e7d637d26b73b5e2c27"
    $a1="91212aaf321c3b4d23503cf40e5b8f01afcbaad1778e172854024e4fd6e4e4303ecc09a37be2a36cb4db97b46564c81a"
    $a2="a7591433bd34df4d505df3b556313a14f89c879169c254a4d23df9b6e5b94feaedfbe4b9475ecbee98168bcd55c605ef"
    $a3="a7591433bd34df4d505df3b556313a14f89c879169c254a4d23df9b6e5b94feaedfbe4b9475ecbee98168bcd55c605ef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23f30319cbea96b5a45a191135b98b8d72d8648304ea3c35ece06aec"
    $a1="868546d685f8ab2d67475bb5a3a195447eddef046e424164c6ffef14"
    $a2="45554197ff700df9a00f1f7e480e4985fc22369881ea3048ffb57220"
    $a3="45554197ff700df9a00f1f7e480e4985fc22369881ea3048ffb57220"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1b1aac4e26b21a901b2a450766a6036d4e707e27155bbf45f0743349cacf7f733bef45cadb2680709f22579faf0618b6f4ac377858b40310f53853d8c1cc4809"
    $a1="a60738163e04c9afb88a9503a99b9bd5d8a5aec0c7c9ae2ce543bb34313e28bcd90cab7aef4c60ddfc4201c66925b9427665a3b8885a86887849bb6a0c3e79f5"
    $a2="dba5bb06a565c761555fb871700804ce7a296226828be1152361117b336ad237ca1ceaf5917e718882f20ef1d0b094c33aa31518e964c555d3cb80f1a0a93170"
    $a3="dba5bb06a565c761555fb871700804ce7a296226828be1152361117b336ad237ca1ceaf5917e718882f20ef1d0b094c33aa31518e964c555d3cb80f1a0a93170"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b2023b1968525e566eb9b94d83fef83519916d4ffb49ead80fbfc6ecb970c85d"
    $a1="3f7924f2b6e8cbe2c109b2ae8dd4c59b37e789f7a5a4467eb95da09694fd4b20"
    $a2="2f5b8e7bd96ba65f4571804d8ff7b8e01073fe400b368bcc2917e2cd5516bd2f"
    $a3="2f5b8e7bd96ba65f4571804d8ff7b8e01073fe400b368bcc2917e2cd5516bd2f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fd055ae00ef38a75c9bfd2c48cea5104d8ab745c2627de58de9f5cf924882d590ae72008a94df81e33e49eaa9db63357cf2efdff6eacb0a5447d68bfdd17ea4e"
    $a1="1a6e0cbfc1e23fd6b43d99b60bc40a5d0b0c8596a00b62b1bfa6572d7a90489b8d82e98706a58dba9f4858acadac0ac71c4c780e3273ce1019edef5a89444876"
    $a2="327166285b7a2ee885dd9d93c733ae8dfc3bc9e9d5788ad241561c3b92ca4f5ea4ff840dac2734ed6dfacf343df631f93b228d8187a76dfbe51d13c28049233f"
    $a3="327166285b7a2ee885dd9d93c733ae8dfc3bc9e9d5788ad241561c3b92ca4f5ea4ff840dac2734ed6dfacf343df631f93b228d8187a76dfbe51d13c28049233f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="af69e6ac5c39ed89b709a19cf1c211421cbee5dd355269d856a6426e28c55e2b"
    $a1="26cf3984aefc77bf032a81cdf879a739a1ec5fd3758c0c611c1b4c7a89f8c8a1"
    $a2="593e27c355373e852313ac66568b7ab72b9570c2a695493a3444607079c98341"
    $a3="593e27c355373e852313ac66568b7ab72b9570c2a695493a3444607079c98341"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="88312723ae99a77f58d0351d6e35f949af12307d075abc6e399cf2dd"
    $a1="3a27b6cfed60dc0b7b38b91d4117cda589846446ea030c76bea3d9be"
    $a2="b2b35702e8b6ba1e25a2a925085ed36b4bfdf0c48e017ebefcc9af7b"
    $a3="b2b35702e8b6ba1e25a2a925085ed36b4bfdf0c48e017ebefcc9af7b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="13b61e204b469cffdac27703d8f4904b49ad8b88d2b4457bc39f02a3b7efa336"
    $a1="4af2f1e83fd909b903dec03d40102b487656c60cf799bd79f63f91ecc7f9f05b"
    $a2="209262095ad0e1d886b2fbb50819a5f4e7dcc0658841893b88e86ba222a2b0ee"
    $a3="209262095ad0e1d886b2fbb50819a5f4e7dcc0658841893b88e86ba222a2b0ee"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b3607f234dd465cbf913198e1e6afc6d4b1b18f058c57f50c031fbfef8eea8126bdd5a16b75ed022e753d323186c371c"
    $a1="3b53235ee3471c33bf9b050c016144806618d351223a389a2b4a0494cb4600d4bc746cda2dd2f385c83654bba2f8384c"
    $a2="a09edc6cdd0e17a66a842e962e8d034bfb66feb6cd9e3d5d98e004b672197111745d65aaf37dd2aef626127055829fb9"
    $a3="a09edc6cdd0e17a66a842e962e8d034bfb66feb6cd9e3d5d98e004b672197111745d65aaf37dd2aef626127055829fb9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2346b577ce31549a777a561f0864855f33c1788af1221756730baac301dd34ca493607f1d0f87f08a8312b4b3fc14260935ef5c523112b11932566056ea66afb"
    $a1="67b2b2177230db288d569c9e6f5da57aade688d99bf7deebc64588297e6da6d3f00012bd325ab2b216ff0807db4477084360e4caf7fe9f2c1460566ee8bd0f39"
    $a2="a546615347becb5b0353590b2811e6a6a8117c9abb42f71451195792c5cbfcb5c6ed9f79a6b0bbd0def2ccef3ce39170c2826aa2bda926cc19cfe70b480991d1"
    $a3="a546615347becb5b0353590b2811e6a6a8117c9abb42f71451195792c5cbfcb5c6ed9f79a6b0bbd0def2ccef3ce39170c2826aa2bda926cc19cfe70b480991d1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_solarwinds
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for solarwinds. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TG9jYWxBZG1pbmlzdHJhdG9y"
    $a1="I2xAJGFrIy5sazswQFA="
    $a2="d2hk"
    $a3="d2hk"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


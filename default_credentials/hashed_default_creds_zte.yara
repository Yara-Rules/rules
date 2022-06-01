/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed50e8c7eb72b1e8cd4f89af085a7c2a"
    $a1="b512c7363366e5afd113029e7cbf5ec2"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="844c590ba1ef3757d88ac4951bf269d17615c87a"
    $a1="9e88eb02399a8947cad2395b01595d848c7a1c87"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="85e2993e1713ef21cb42470c22bebdda1cfdf29a48cd8ef1edc8b9651f7ef7b181c260db565f12e07a6200f8a5992025"
    $a1="3aa4921f19834b4b445cad30e6a760ad7998f195e34b16690b74e7b31b8da1e543cd23ee01c33b2b8b907de63b086385"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="289c88d937d35f3669c94e2ad1fc9f56d0af0267683e85f00d281dec"
    $a1="037921f105c0ad458943f805364d257f4daae2498a302d3437a96bd7"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c608bb59aa76e6ad37bc1c9edfc62edb0a57b5fffd98e1a5e7358c0b245a30c910bbfbd1918a124cac7878e71fe7d469810d85fe92f93977b8f49aa58ff9f5f"
    $a1="4fb0b502ff286c02473bdf07f55ec08eccab7a232ca1033f8d9b6a00c125788b13e5dfd0c26ad49191759496e8f0734d78b6111cf1cce87eea0c9c9fc1870d6b"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68b265878c455777a7b72e200023ba1ae40e8f4711980301c24894dc57397fe5"
    $a1="7b4740a6da9c3f2d91862a0b9adefa9d9e137d3eca72015babb8a95be16b2506"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5e42125e70ceb375f8af88ed9c0fd8af0ce4012df0ca3091251840e355dc39dc6bdc380937aafb0e546b9c9caf025568c8560922cf7568e9ed6188ec0aafe187"
    $a1="708bfd626e1068239a806708995e69de6dd7e9b8dd4498e3576badb863cbda0f4adf7d2b9228a187958e8c73cfd1f8515b713628b00e52e0d1adad35143a38da"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a21604fd0fd9899fa037315816cf01641cbc09e6a7e14b00bbc76fc233953fb2"
    $a1="43ff7aae0202244490a24d2dc387a033e89de77acc8176cd21ee10640feb9197"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6d44a7d2bb55aeb28c4dfbc50074355b037dc92819ca29a200d6602b"
    $a1="9cd34d2002e0842320aafc357167e172a11f3151529f7a18a5c40e1d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2e228e404125b81011357b353c738d18d018fe587fc6520c162f6bc654ae0663"
    $a1="8770aac7db0cf2226ea290034955a49bb59c69e666d5d2f1b3c77ed50340aeb9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3f96b2db838678ffa54c4e255c08b57b99e1ddae50ff8a0de2b2b44cf21f8c8d67e7ffddfddd9b09bda8df6c768c8ff4"
    $a1="2a1caa6a50da964f85291200f3e4dd35f49a634dd18620d736457c69c297724187fbc448018cd480adc523f401322f65"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7841bec97afc1fce68d833e1b37f7ac9a5acde407ce5ca14a4e481b61047aab194c7c2886599bb5c940158c8bdb8906557788dd0c172ee608049aa31543eedfc"
    $a1="ede1629e063689808f7abb5355aff8599039f1e4854eaac0a351aa7f2bc70417c393af8bd2db0d77d827d421ca18f2c4b3800fc19ea8b4b94c35b294b864a168"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_zte
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for zte. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QURTTA=="
    $a1="ZXhwZXJ0MDM="
condition:
    ($a0 and $a1)
}


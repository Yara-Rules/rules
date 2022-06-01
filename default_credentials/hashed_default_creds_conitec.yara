/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7efd721c8bfff2937c66235f2d0dbac1"
    $a1="69a692d18dda77c2ba3de85548d7bfa0"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f941e1206abd4a2d8889da67be10151f429d95dc"
    $a1="7c9ae26d2578c617e59f8f4ee13d085d64002967"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="596ebba0a848db6019d9e4a6e66222d174cb710d9c0984e0e3b881ce1fda25389aedff13e06d82db76661093e712f5db"
    $a1="50fa38f83bf0acec1e6f9486a6e00f2abced05b451ac26fc91adabe8c9173ce100071ba42932048c080ef21982a7cb39"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bcdf6c448176da40e0dc194f422c2716168969aefe1e965632d71d3f"
    $a1="2b3b3a2babe1007f0905e9bc6165c8b7c41010dc1078ec61cf2e4241"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ddb01697ab4b84763cf27b42324e6938946d41913e0e1181921d6b2c0e955218ef7ac25bef212de919724259e389fc12a7a49c93f2ce5d4b3e17d3c050fbc251"
    $a1="26ec02cf12f565c6c93be6f4d08afd9898657a5d33812b014e7dfa76baa560ddf0ad12a26de2bdb240c666b4b526d9d64ce139ee824657a2d9b52d257d69c996"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3f0c9b03e8e39b03773c7ea7621035cb6fc947cd41ca7c44056d7e7bbaebb3d4"
    $a1="96a6aff88e4ad2f8eaad8b9e47d8a00a4c4a578cc6ae5d01c70210f0c6d4bd94"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="57d19df1bf7aa1be24b7cdef2042043b5f9fa65f742caf1aa604f82625dd91f6a657b2ff453f91cf7ec071394c6afc582c0ebd26f8a4215e7ffad83fe7703002"
    $a1="ed6a925021ee9b8e62df1ebb9bc5f761e3c1f5770b7b4664fda403ef20ca6dcd3a04631affb86531551bdd8abe1ec3a5bffe645b43e3d55e43bf5e9a37aed994"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="acdbea4c52c7ce2f563c885fea8f74acaf981100729ef22715ac0ad78bac82ec"
    $a1="e37fa5da241cd4bf8f408d6ede830a440c3ff97d61efa7d8fccc8473b64f1d06"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0ee9306da568191528a34a806bccbc1c820f47bdbcc7b71b473f013a"
    $a1="191945121dda0d1a049a613cba4bf53598650a533ebd74445cf3ed1b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e403f044b9763e9befb491e795b12508b9a4786ae14b15edaf4148694269c79c"
    $a1="8d0d724fdb69c8554c06d391ec7e34fd748e818803fb3b14d8d5cec73e099355"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="02ab0c08840ec2a13dc732ea81b0f0b8c8ca2fe02c3c0d3a81be2c6516a6dba5f086a5cbbb1031c0af2eb629fdb02130"
    $a1="9ce4c4f209549cbb92e1d7e83bbe808d7a638004243c95571f77df3fec91638d1b27408d4019a0c97699e38f73b0b13a"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0ecc5b78ce2a283e7d0a74cad1d9f92b3df9b7512c8b998edcd9cf2f13eeb86ab2e80f6137d9f802f33ed394aa40586b1f899e4291321994e40dc56567c45344"
    $a1="afb67f116077ba3cff41083bb7de39420b9200633e9e83d844daeadbc08b8673c6795388d4b4014f236f6220492a08b302ceedec5ed6a33e9285dc181341002c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_conitec
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for conitec. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWRhbQ=="
    $a1="MjkxMTE5OTE="
condition:
    ($a0 and $a1)
}


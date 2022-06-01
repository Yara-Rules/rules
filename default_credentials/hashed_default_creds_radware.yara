/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="351325a660b25474456af5c9a5606c4e"
    $a1="351325a660b25474456af5c9a5606c4e"
    $a2="63d02c36e983c2f5365c74b3b5a6fb29"
    $a3="63d02c36e983c2f5365c74b3b5a6fb29"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
    $a1="d44294dabb5559d834f8f8d1c5d4fd75c165770e"
    $a2="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
    $a3="a60a1c7a9d688223d948e83e6a2cb40cd7c83f3b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
    $a1="5d51df127cb09685d20f2808a179325f18d41df55a6b65a3b0f982ce6377b79c06877eb66415bb4c9547d7ca0ccca642"
    $a2="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
    $a3="50acf6854ff049011cd9187fd75de3d3f3f58c1b474fbf263b9be441811912ab269f93ee2020b1a19cfb9996243b506b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
    $a1="6deca2175bfed6830906048cf5ab2611b4fa6b4e2394309ae2f6832b"
    $a2="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
    $a3="1f2204c440c9157e336938952ff3a2639b1c7e4fb29c168d98ccac9a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
    $a1="0fcd307f76f7ab45e0e49269f6787552143f9652b394a2720e8d61a754841d815fcd9b05c7613ee746ef7e3ab5ac17421e08f3ff8d63f6a906177266fa0b2f69"
    $a2="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
    $a3="e40c136d125d5b29d6de7394f2617968aaedd0d9f6af63748e3d35711de1b9a2fb5b63899b1bc8bdaf243625ccb2f003d11bacc9fe0ad1490472add97ad769d3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
    $a1="0a7aacae9b43f934498185566d2a865ef93d4f4c4488c60d085f5b268c949825"
    $a2="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
    $a3="d8cac552ef22e00eedd1f54b5a6e735ff57d093eac889aad542dda57c585d01c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
    $a1="1fd267661ad758bb5cc76b65daa7f3c16b35a5855b65d2e509596037845b03be5b41fb1b74161565b4c85c868d0a102fe1e7a4f2943b71691dbd7d41c6d426ae"
    $a2="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
    $a3="0da581b9fe0281f5d04d298ccaa56596b0deeb535c3c2564d370af01fc835ee9c99a116b169550befad06577064382d85df7ce90330d1198e6e56afec7fd6620"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
    $a1="db2bbb0946ce87b56a027c63f2de00223d07b806bd6f24ab81b799056d328840"
    $a2="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
    $a3="241c62cbf017c6d86c6789a12685ca53b869447d2978836ab40a64e0106e4bd8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
    $a1="37a5be8930801a88da62fdcf696d09358fe48339010d2e10db5bd13b"
    $a2="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
    $a3="2470d6b818c2b7cf4b177929f3f5d8092307085d24aae6b77f634021"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
    $a1="c608b6a3b40f0bff5b6f781631392445083f63ae2ef7557eafe3cb8a372ff7e5"
    $a2="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
    $a3="58957c092f4040ebc115fa2d157888165595cb4fed30cd169b944ea74121a1d2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
    $a1="f8f9c707a1f74cd3f763ac6e68e054c68baa44e0ab670690906de81ae7a54af528ea88379d07e95793fd6e5c5bf272a2"
    $a2="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
    $a3="3a2259bcf601938c1fc6e92ddd67df56647f0e28a3ff9d206920afd922e91ed082330e9259338120837dfc475cf2bf52"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
    $a1="27465fa032c1b4570bed0b6cbd10eb1bda7363a5fc498e605a57f5a6710c0e2b88b216a7f0f769024006003e59c91ebf1c135b2544a7730f3030aa6066af356c"
    $a2="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
    $a3="a221ad4b83384a87429f1731409b6572699ec55ea9dc06900548bc22c149126f7c73c3c92fbc4b75386924242aaad351761f5b96d33188125908bde290e6a83a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_radware
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for radware. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bHA="
    $a1="bHA="
    $a2="cmFkd2FyZQ=="
    $a3="cmFkd2FyZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


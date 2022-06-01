/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9ab4782321ccb984679e470cd8fa685"
    $a1="719046e0ec013f9307ddf09ee231a0c6"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1b7c543500f8f9d184acab960af690069db2d4a7"
    $a1="3a4e43903aaddef44ee7c8773c173d2c72f9c93e"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="353e2073997b897542254a1e667e4c96d323368a990b9f3b17182b2284a984efae7814ab54153086e47bac672ca21646"
    $a1="be5a2a15447b7344c805cebe857fc9e392dd961813990d48a5caf265aa02717f4f3631c2fec1e79cc9130b4d5ee00e50"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a4f4c656275be4ee922edc76733e8a8cfc1a663cbe290c8c8df801a3"
    $a1="ab2e5363e690c6b8d7872a4591f84318c43edc993bbd3377e0cf7a22"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="075623ab889d3ee9cc33a688b403105564abfbffbd9aecdaaeada5e3284f7e0496462f3acaa3e80056eda90bb5c9e548a958eeea796d5411f8acf8b9012909c2"
    $a1="43b6706d02941af0d28ced9d9bf5592f84bd9677233524dc7567a99c7d34259cf238149b60711023534cb66a1097c4de0e72f29c9d15d4568acd7068c3f2bcb3"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9f132b053488478489310e498069a7c6dd58e285fd1f7b18ddab98a5129643b9"
    $a1="ec0fd2c691694d1a66b4fb1aab926cf702d4fc8e0337560f52a735c6c2001c3e"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68b6cc0a781688a06e4a65e73065ed47a10ade4977c747140ca08f8e08d27d4a2933f91cad80683008a6854c1907ac5af3f75c3755201e03d4eb6c89cfc8261e"
    $a1="3b3a06fd0438a5c4b00162998f1bb66f08d45cce1eaca416389ed1a497c0e9beeb241e2717edcc3caed6a902bd02af7a42de79da9a8c548dff5396c8e22da8d8"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="636c18aaf425ada0f1a5e779a1e37e1e9fb30d0230d3ded4edbddbee51c64676"
    $a1="26dd7e433abac96b79a89055be055867db4e2bf60ea688eadaf87c139046e149"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="35f46e003490b83903fd8165aa0a7e8881bb1cbca226c511a0dfc0b6"
    $a1="53ab274a32f70d8f7ee043b690d2144eedb9e386b55eb1563e60d02b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="825481f6b55770445ffbf32ad3ad1c064f5cddbb5c7e9918241a68e1b199e950"
    $a1="45963852597de50b0adb2c5626714b83a0fa632478aad8c08b8f1621eed3cb79"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f91f4efd0c7ec979aeb5ac81a5d529319c1ca0606164bf68f75f62b82c9abcf1b875bd4360e01e385dbecf9e3338d495"
    $a1="a50c39664eba4988e2eeb20138a14863411501c0f5eac9191197f30877e1267da9b3fead721fe813b6aff277cf432d4f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="04c4eabf89c28c474a169a72f117e876be91027898b20c5ce0f85ca65e5f458ce16d3383b124cd238a586836113643564505a7ceea47a5b5685867489fca6e35"
    $a1="6e824f72155e21924ec1b3419e94d9f0d26f8f984c963e2a4a30a81758a86dfe84612c4270615517f2e29d43af696969115af2b4b06ea2806f8a9e4db3235daa"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_kronos
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for kronos. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="U3VwZXJVc2Vy"
    $a1="a3Jvbml0ZXM="
condition:
    ($a0 and $a1)
}


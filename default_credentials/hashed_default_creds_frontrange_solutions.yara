/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eb0a191797624dd3a48fa681d3061212"
    $a1="9df3b01c60df20d13843841ff0d4482c"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4f26aeafdb2367620a393c973eddbe8f8b846ebd"
    $a1="0f12541afcce175fb34bb05a79c95b76e765488b"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="233a0c3b653358b1b07cf093e7b2e36a54bf4c66d5736db17ed145b18520c9108bbd9ed53bc74de041e15f1476013b10"
    $a1="49e18e684812e9034a6c1eef90b337cbc9ee8de6383e57b79f4bc255393417ab33def30f0f3398c5489c00faab52a619"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="79f95ce631a460dc2e3d220a5dffbb5616074375648e4a2212127ecf"
    $a1="24289a24be5d6ee8df8f3cedf9b538b4cb69fbaf8abca98797b328ac"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="353ba90f8c0b3e0f355a3d6c960b7caed5f2c1412992277c0669a04a62e7dfd35fba9f4631a7dc6d00fb44d93d305cc0b749c7501d9ce86f26148d05101b8324"
    $a1="932778fa1dd9a15dac1f6d7690b29b70e9c205a8d2b4a437f007bf6df4fe3c5200520078f95184bd37ce6ed67f362a42b4263ed4c8ba6d777b0166f9af879897"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc613b4dfd6736a7bd268c8a0e74ed0d1c04a959f59dd74ef2874983fd443fc9"
    $a1="a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="33ace3eb11c517be804f516ab407838b51c6eb5baff3203ce3a320b6750bd1bcbf7091092555a332abc4d467ef3c13fcd9ff5312aa0036b98ff1b29774d55f4a"
    $a1="3668a081b0929274a97abf15209dab17ae30a35a7751a62e5515262524cb38b5216cff0ed604cf6a8f5f5b573aa0573735764a99a6028f22e0d2ea1eaaac810c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2f185fbcef16ddfab9451925d69b0af28181a7a5efcfa9c6b47f76a2aa430e9f"
    $a1="13ed751afcecd936bcbe496a38545e63d2fb97f2ad8fc5b72f17d29784c34db5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="03370c307219d3d33781c917e10df30471407b8097cf71487eb63c69"
    $a1="a86118aed12772c63e1641003f22dadc2be7ee74d4cb33aeb0b3466d"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e5d79468855b0aa30152460f869669ebece49a748839c70f19d17bb2a2239e2"
    $a1="1037f1f67277cd916301c10e5417b95c117abbd8daf2b794c30a90ee67898b53"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="06ff6516b10e34580acbb5f2b05ae2628cc1c661fbb3e50b31dac0d0fc5be94784163e820aed296a54555a0d4ecd0190"
    $a1="8515c138c59d8d72b3d9ec1bb64c0ee8f1d8e270d29c1eb632b0ae048661bf0121c24c7749166760a022f8c2d48fab62"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c56f59716f146eba7b862cf6a1443e68a3cee348bd8a6d51dcaa1ea5c52b41692ebca2e96063db57158e82f789a429d2723b0d84c3a308e198827399448c9090"
    $a1="2ccefc4001cc12acc9512f44784c55dff5086894fd436dfcb30f64a2c5a55dbae984b86c749d29e10254c770f3b21ca6fc11d84ddd9077db29c6e6bcb4c48f24"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_frontrange_solutions
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for frontrange_solutions. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bWFzdGVy"
    $a1="YWNjZXNz"
condition:
    ($a0 and $a1)
}


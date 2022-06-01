/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e0cbf0e62d03796f31da47099682b72b"
    $a1="6c2ffe76fded433599c8a2f07a69020d"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fc6783b3cabd4c09ac7a7da84529f783c0e11eb2"
    $a1="71bb72122906ed5e8d8b40796f08417133b5bdb0"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6697f95267a06541d307b844b985b47804c52ddf4fcf66b0009168cecd6448d5540e23c1c5bc3e16f86f58f96122d08e"
    $a1="74c80d057102786413d6f7b6a92759d249204aea7b4d7eee379bf69652b62180d1598ab045c2db9876432d4d303c0811"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20f6c8d59a3d5399b5c0fa326b0e2f9c3d0e8c39281ce43ab2b77c4f"
    $a1="60a8ce9ce8c70e0d4c85eebe6951c1d24f706b3baa0d592d91d5697f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="349a41e67bd69bcb66aba203c61d4c58e9912b1e46aff23bcb6ea6fab11cc9cb8bf25c5187a1b73f53d31be856fdf58b0ffe662e6df96ababaf2ae6a9c838cd5"
    $a1="6fa83d5060a82a8e4dce608745cdc0e4b5d44396b98254497ce2e2f8c0e2d876d43af6461436bf2d397b2d4cc9336404517559922ae0e7dcc28eca7749bb7aa0"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2d531b2112e4c16073a070d4a624c05872f06953f7258add114e0b3fbeff9041"
    $a1="bc9fded673068945f828688898de3b94db0e41a733d939967ca3b29b4deb8970"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99ebd811fbcd8b1bb1625fa439438c96e9649f68fdb04954348d4d4bee19d1682f1d1853077f903c0a82928f0f1a8d905fbc764f26b0dcb178fddd09ce123922"
    $a1="18b965fced71cdf54f0a5cac9e26fdf31d02f7f70da773bde4cfbb7826be45d6c11f29468ad6ea5a4c972a354d28148d65045c6e5d3905d1f17d8af5599f48fa"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="86c5e305614ee4f20d79c55342f8335df1b7500e6e246ef7e9256aa861223012"
    $a1="cb2bd491a6e91e1e1745d88d953dad5d8df28f471288d85658a14d8d26a05b2f"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40f44c8b73dbe03aa481b740850e444c9a0f32cd97c14ed878b7c7ab"
    $a1="b92c656edf53b0dc2ab8ba496098bbb3d502e8c43cf6ff549f7507b8"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ca99d4ece01b003edffe4df8f6cf194070787c3082257836c6a3486bf5512c73"
    $a1="1c9aa951145d924fd4e22566e13502161a46e542ad3b9210faf0534536e70d06"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d438306fa611925107fb89a7248146a396c00ecc168a0b57d0ec64e8322d6efed561e206679f26411921844994d63fcb"
    $a1="fa9b7db45076f001e63325202a93191aec6690f9028a9e063ff6b72d600dd8eb0414e35b7d5b0bcaee58062249fa3486"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2df4dab3baf0ff7e54bd1cc0ab00640d39ea47dd5458502795169cf472b4f7c466f0fdd0078785050ab781ec412cf0114c897f3876e1d8f458aba1dbb4eaefc2"
    $a1="733bd53e4a4f1ba0ce556aba06580ff368da7b6404a7c4569350238a03b56dc56a4c0911bc360839ba1b22adc900ba54924ef466b6262b16d05c5210efacc698"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_accelerated_networks
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for accelerated_networks. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c3lzYWRt"
    $a1="YW5pY3VzdA=="
condition:
    ($a0 and $a1)
}


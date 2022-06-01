/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1a6a90771aef72546972f0e79a995bed"
    $a1="1a6a90771aef72546972f0e79a995bed"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="de9827107d3499a098565570b4837c85cbb53d99"
    $a1="de9827107d3499a098565570b4837c85cbb53d99"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b00841609ae946c03a7df6b0093076ac3edaef95252a2b9efe3be73d0c356a1269e251cfe968160eee633bad581eba18"
    $a1="b00841609ae946c03a7df6b0093076ac3edaef95252a2b9efe3be73d0c356a1269e251cfe968160eee633bad581eba18"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b41594ce287862eb18fcb1929bca9479b804a342d8525019a9894fc0"
    $a1="b41594ce287862eb18fcb1929bca9479b804a342d8525019a9894fc0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="15bcb0aa64587ef8b486b222ba52d7371b873ce5d286706a5305dcd6393ecbba1282ff25c2620d7293335272377dac767c6396fcd1604bb64ae687e8b9c0c1a0"
    $a1="15bcb0aa64587ef8b486b222ba52d7371b873ce5d286706a5305dcd6393ecbba1282ff25c2620d7293335272377dac767c6396fcd1604bb64ae687e8b9c0c1a0"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99244ee9c3ca6d758485858bdfeb5c5bf3f6d786e4c2fb78f57ebf21ad6c53c1"
    $a1="99244ee9c3ca6d758485858bdfeb5c5bf3f6d786e4c2fb78f57ebf21ad6c53c1"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e5634ee87939a9c6c620708defd8d049ee93d3bbb189bff731946a1600639b30bcaaca90d58b5764988e549d289b22c64ff4e2379290407594f457ef380bdd36"
    $a1="e5634ee87939a9c6c620708defd8d049ee93d3bbb189bff731946a1600639b30bcaaca90d58b5764988e549d289b22c64ff4e2379290407594f457ef380bdd36"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="98557ecaddcb6b5724063a5044805a91e2d0c42c08d9cc36fc15e33d1b788c7a"
    $a1="98557ecaddcb6b5724063a5044805a91e2d0c42c08d9cc36fc15e33d1b788c7a"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="719b167a6a26866d90b5031350e77e0d90c1cf15e1b7563c09a68423"
    $a1="719b167a6a26866d90b5031350e77e0d90c1cf15e1b7563c09a68423"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="76544ae8db0e95efc605e8f44d4b0fc0e10662ec9516b897b7a513e3c1e7dbb5"
    $a1="76544ae8db0e95efc605e8f44d4b0fc0e10662ec9516b897b7a513e3c1e7dbb5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58dc5ffa280630891231e145f331ed8984d7ad4f989856cb8765aa50132b08aaca634b9bbca0abaee97dd2642b87180b"
    $a1="58dc5ffa280630891231e145f331ed8984d7ad4f989856cb8765aa50132b08aaca634b9bbca0abaee97dd2642b87180b"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a971232f0db52853a885080b1ef65131f1299e8c6890da053e4a3ad26256bc4881241fa5bd71baa8bfa2d525435dc9ac1aaf90f83d626ae9606db714512baf01"
    $a1="a971232f0db52853a885080b1ef65131f1299e8c6890da053e4a3ad26256bc4881241fa5bd71baa8bfa2d525435dc9ac1aaf90f83d626ae9606db714512baf01"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_bewan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for bewan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YmV3YW4="
    $a1="YmV3YW4="
condition:
    ($a0 and $a1)
}


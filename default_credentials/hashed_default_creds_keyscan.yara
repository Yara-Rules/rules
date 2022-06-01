/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ec98ddbdebf88abb34f8f213b7e5fa71"
    $a1="d63cbd70b6374fbb86b2d2dae8574dc9"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac284f32ff639cb7881bb44aa5deb6abb9d13815"
    $a1="3ba2ff85499e18bdecbc4140476c3a8bacfe9ff7"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="37250cbf78a7e39273a25eae54bf10f6edcfe414c61db87ca7e93c6d4cb0feb9219dc5e44edf13085afa81cb18cb9f12"
    $a1="dc9f616ec309a570a8ebc5b7209fac4bd47cf9b759f39e7f7fe40be4d21022be5e6423f1377ee51a8fecb47a8c1e27e1"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="14cfe7c06767d8a8a8f8dacd595d684dc60c4bed76cdb89a80c1eb29"
    $a1="9c633405fd3b19f174038f555b4c61c8e0f17e839257d67dd4916bbb"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fcae92a850cd17f5921a42d325736beffab3cb664ba04319d7ab4a4f2eb43efd4c5be41e5323e3d86180eb33b807e0e07c21a3e98beb7ced33e1d531fc06e704"
    $a1="06ff6f2da1670621005ace3ef9362dee318b9a3c9d30ea160b3ace253519693bcf9fc9c25c5d57b4b73dc8f5ff305f7ed121c2155ba8591bd90fad6bde2398ca"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="620933380d886ff848bab95aee5569024a166cfd13293aa8a33aae52d4569643"
    $a1="5838045ead07714510f1176841229b3bebecdbc05a1abfc960ef204092207e03"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0034d1c7efcdc5add18c9cc1fab87d63ccf579468b9d778963248c38b6c751bc16de015298927e9ed8354a894a414709166009c1743eabab59dd3c1aee0a769"
    $a1="396f6050de5cdf7c3d4bbcb66a5b668d21b5f77c028fbb2fee1d537330632d0be8b6019d91adad6438083b2f6ffaf580fd82869c4ea19eadfe016fe0d871d025"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="84db7f357641d93a7c6dc763af8a889478872674f61f38b9f5a1ee4834ca56be"
    $a1="5de87e1d9b15378fd13d13a182f7e6fbb5fd3899a812989cd427aaa18d0980b5"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="06a1b31131dcc9c6a43e1799c1fbd64f2b50251c56d0abbea18a4c51"
    $a1="79a11203303270f214dffafd593c894786b32dbb88ecc498312d3bcc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0ad9c4345af3932fedd4b324b50bdb93c0e102f68a1298de0ad2d0deabf15144"
    $a1="8e1fa77089b1b0241df46ef0530c799e9c2f3a0a6740ef64924a21aad30ace5f"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a186da0e457eb12ddf70cb4c25f54ce36485667d3a3176974c29e4d3ed75ec769a612281817487a35bb80c6eb69f03cd"
    $a1="d7c6d71f8510dc81b06844cd1cb12df2519127c1acb33a7c28c48006b7d15f05e4a7b0f00f29e7dce39c50b89f9cde99"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="680ef530485de33cd370f3b8c26cb1c644b168a522d83c97d9227736e75adee2627af14898c65c90eea83125aa92dc88827e7946cbca9fc214fa26cdc4b1c21b"
    $a1="4353bd5838da494f1212aa040c2738d7285a87d9590752893ba958d4ba43d5c126baea82df977419a6d7437f5be05602f2484591aec3e44efe7fb0d216f9a999"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_keyscan
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for keyscan. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a2V5c2Nhbg=="
    $a1="S0VZU0NBTg=="
condition:
    ($a0 and $a1)
}


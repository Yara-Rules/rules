/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d6185f8c684d193324b1a5ac7c74522d"
    $a1="2af209a360a2217e0838147bc405aeff"
    $a2="09c531defdd28af54ed230c1fb8bff32"
    $a3="e3502ccb6f675cb6e339361b4aa2dbaf"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ccc855e748bb342ffbedb1c2b98009d5cdf3fa18"
    $a1="0bc37ca9b9af504a1345f74802083c0f57598cd8"
    $a2="2129b66413b050500f56327d764d79a3c5906078"
    $a3="7b79979f92760a866a10f43c74fb37ed6013e482"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5b0b72d2f752ea9de3e4d56d16fb629d77657009a084b865f6730f283df9ea23641c53dde4bdfad42868a32bc645668e"
    $a1="120197f4c2c07b870b9689e297bb28f03f722dcc7d003bb0dac3098a98b6207cc54e6183b147811bdc025a85627d94d6"
    $a2="fcb772663974e213b9c43e4e93c866a9d337981bca733c296d1b316c71a633ca42f39fc1c8656e0da7f32484c4b3d6f6"
    $a3="0d2d1c3c3f720ed23fdc8d9f56e82167652c32ee5fc72d9929d59abb25679f7457c5e7a4dcdda50b921125a4511e74f5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="68fe22dc09250aa713a1fb5a00d225f01129c5b0f25f829b5ff67c54"
    $a1="e4b20df5577bb098273e488f2d8905f76f3a636abaa475a2905f5ece"
    $a2="2e6f0d7df8589a2e439a62909336e41a2c582096301843337eed1478"
    $a3="38edc88b3ab1018661a57dd4f8ec4bc52e5363b9cb1dc3f8df7c8fa0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="20670a420665c271eb91ace67038f49b64998b3b109aa8b180bdf3861dc1eb87f0c272f4bbccb6de642cbb2ed592a214a46d1044d67b8e7b7cbc5487546e5734"
    $a1="b432b0a9c70edec165669f331d0d035eed2296ede52ceaa43822c7666ea684fc05b8f80f29c904a415221ce1ea218a7a4e71a30fc10154004de5b67b7ce4e880"
    $a2="80ba8241e014953e74f66be1c04fe0dbb59d8ef800fae9968dc59890e2f607bddb596087c0cfb9af150b28834b49c06412c6fcec2244ad6d2be213413a9aa1d8"
    $a3="4ba64d882ad15628b03c4dc540c0fa632d6b265d0a0b3184e2d99087cf65e6f4fd1fd8ada5e864d80a692c14488e5857fec2296f7c235213b74e89c59bd8c5b7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c6707bdeb5297764f5f202a754c931e6f4dc5808a61278e34b132f9f145ee996"
    $a1="9981b28abf766d92c3761fe28a1e3f7732310b45e75f5b349b5082e8c78f0676"
    $a2="f9ccc825e2c582ec62a6b3b62931579d652c5d338179d77af50a327e28e797e5"
    $a3="b7e20440296364fac9a66a07540b1c3acb2a913b6e903c5387a8bd233535a765"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dc5a49b3fccdc43a41af195bde38728cacd9fa9ee74ea8cccd0ecd2f49ddc3618a588bee7714fa9e53efb3dafa83bf299e0bf8da3614a521d5bce313468868ff"
    $a1="747bcc2ae323e3e820b0c5c07162ff3e5c9e8ef500e8c8313417cc809013a058dd06a4d877c101bbb3b80fe845b35591bf3572bbd32e9bb5ac04fcb541acc94c"
    $a2="5bcc70deb6bd2c59c087f76d8443080c0768cf8fa1f44400a80d7350e1a7b543915c44f0e5252b77189a843ca5f7f3e478149557f95644bab6243fb4915b946a"
    $a3="cf913b1612a0e67848cb3d0f4daa418eb073c52426829d31406afb0240d6e03a28e0a0256b5b71909168087ab7d70c82d10a7deceb1bfd84d95448b06c29d7b4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d9c31246e6fe87b1fb88a900da2ba135d2a22296810bdd8f6c9124c73e947d59"
    $a1="cbadfc8cd125762e84e59e61bf19a60c7098d3beb22e6659e5779f1d7d8d4894"
    $a2="831b8a29999f74a7408ad4952ba8d3d0ef82b0c9970869d53422b1ce8b782295"
    $a3="c94b5aa43d360c0035db4889aad8b9719ba7404d84358ac171aad6f5cfbe3902"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a0d2175f9f9596a4047b20f01a9239385c2fc7822e61127d075d7e30"
    $a1="a9750540563f25903edc2f19cba4ab7a387ad8eadcc4bf6c5f29c8eb"
    $a2="a8e2d807caf86a6b68078256e81d65b4e4ad8196aa90a0d5f5d699a4"
    $a3="eb3dda4045565b3eec506bd3944eb6d6e3a3567e8b529a52fa5b8f22"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="40949c5e0e3b5b2daf7d42826f8001a559b06b19d6eecbc20c7b854d6339425a"
    $a1="158eb0750556203dd8bd4b33ed14eb1edc1c288179976184907382ceaf20f876"
    $a2="6a95043d52b79febc32cfd56092e0fbc36cb691bc88491da6f9f509821451e85"
    $a3="25e2ebb10fe636c7409d4eefd998175dbbe301b55440e545eec48b5b020b97d4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="64fa80ffe97e207d2c8b8f369c04d25d4fad0d2e6265adb99e5146b2d5dd8ef3646cfca838017456ea58fb870a9d2b49"
    $a1="9a324706333efbdf4cc3434918eb0b2bf21b82c0ee7011441529362a2f90ca881b558d9b384fcc4bfbf5b59d503beb48"
    $a2="e7f5a7a49fb75e61ba40141201a09a53aa5f38e91f98a1ac47b357ffd748b69f4ed2ab06c85dac35cc90ef1f3bd1858a"
    $a3="7c7145fd8f72d12a0eb978cd3d7ac867d97dd69f6289cb1ee72d05427101f90ff978d4e799f3874f62e36b4d88afd75a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="77a4ffcf3e7d6224ee81d1b7e58b0079ef220beac3337e7875e68773c5292a78d69c6628b201d1355cc6289ba576942375cbdb830a3bd7c10ab16ed85c133ea3"
    $a1="babb1dccf9b88a18531c5cb76313766b91236b49c6af06028fc064f3ef3e94cd7a48c9197dc8807681c05facf69369491814abacb2705c30f59f87bb49aa2551"
    $a2="1b36c520879007679b5e74cf3323952a9d4d82d86f7678588a163ba7537084903a23911d2079412a21a04be3724d82dc27e83f81f349d488189f2272769c6808"
    $a3="93d604ddc4176ed4d2ca5f8d94e3b50d4ea5905e297e4eb1ff334005c06c681c0da1b4924970993ebae42dc33556113b39f45db11020063615496d56b74fe53d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_norstar
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for norstar. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="KioyMzY0Ng=="
    $a1="MjM2NDY="
    $a2="KioyNjYzNDQ="
    $a3="MjY2MzQ0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


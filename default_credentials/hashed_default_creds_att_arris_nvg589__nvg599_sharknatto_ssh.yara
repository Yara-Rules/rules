/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e6c830dc5c2f705525d13fb1c89573f2"
    $a1="519392b67a4702dc13e42e621072a386"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b50fac40a37395792e3a4fed6f13e5121132dfbc"
    $a1="a1ae26688356eed4a15cce689d35ae2efd877b1c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a394d56e5cfd14a2d872e70e2f61aed1a572b3e706afd3eb9e65e4d3008ef5a2464066a12960343634ba7a9fffe456d9"
    $a1="27cdcc8448efee8b04ec7bb58d4b50db619dfc4166e349f5f86932307cf031aca8f10a5e7e8543efd7e58a3140606283"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fde7ddc73cbc578cf3726b47e2338847243ab8cce206a9985c4e3116"
    $a1="56dfc82f1e68e30eb8ce8729af494549c5336895a8eb4f6905f599cc"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b648c2fa91d28a64c345769768c9055508a06212ad7e2f0372a6978b8d8b687613b0929aa9e8eae04c5023aecefdc641ca4cc2a5451e1291c541d8efd4681325"
    $a1="e9b354d67a5ff748e0ef03204a681423a01da37f3cc4d7498485f233ac44d5e22d08b87516a7377d788fbddf033a4ea3b56e0558a8d0bfab48dc5063179fdf05"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6ce5a26221cacd6e272a5ad95f109d0e7a0bc4419f2d979e597fc7e16b7467e3"
    $a1="29e8567beb99601ae9c07d77929d6e378590bbfc36499270614f788bdd6d1bb3"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="91f3a5c40c87651bdd2383f5b5e90dd1a6e0178cd3e8e7b2113340e7bf192506b5c03fb06720c575936796bc6199c405b98ef2d00449a813bc860fbb3b0d34e9"
    $a1="052f738318a08384330a6b54c4a4ee7b637429bc655871f738a35068361147eabb258d19b29e99dec35710ae386310b5f19ff1c9179be4258bd1734b497923f8"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e310981003d25139743bfd09fece1a321e14162416e72411647ddbc50733f34c"
    $a1="2e20d0d9640e94943a7cef90fc5d4455066b478a606d1468de4cc46902b63a24"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="706d6594c5492ecfef43512bc21def5d5c1ae6c5fc268b5b6f166254"
    $a1="e3694224d5210b0a41360bd23cdc137dae769bdc86f5a31ce3062d83"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="914898a2cac6612ae207e62ad6382841bd96ef4732668a7bb326c7507b53ebf6"
    $a1="fe00a89ca29b4d00735d104cb1a39fefaa173f7420274f108616ebfad1088cd3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="090a6fb8c4f645041204999bc707a6fe07fc75e7dc71cdeed4aaa45d78abcd22b4efb74bb31b1bb0a1645ea3cbb946f0"
    $a1="4ae97fc8e8449c825cceffee898ca8b9309ed586f80cd1352616da87e2bb521934fae10e8b77278ee57b2977b915f370"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3779292983f4f3b6f2f131137aa2c9be65e3efefd948821f1245c8a4f5307ed763aed021efee775b4820278d15450c974643ecd1131ce09afcc41d99a69a8ecb"
    $a1="4b0ee97ed4963927b61130bae71a3d1bba78515ff6484f6279360d815ac273d5da0d7e950206a9e987f62c57222482cedf6565a3358b2a344b155740ec9e03f8"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_att_arris_nvg589__nvg599_sharknatto_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for att_arris_nvg589__nvg599_sharknatto_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cmVtb3Rlc3No"
    $a1="NVNhUDlJMjY="
condition:
    ($a0 and $a1)
}


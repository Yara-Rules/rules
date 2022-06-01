/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="51ade87756d148413bde1bf7dc2fc2e7"
    $a1="51ade87756d148413bde1bf7dc2fc2e7"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d5fb0d564e2db3691ffbbde90b3f1dec7fbb4c2e"
    $a1="d5fb0d564e2db3691ffbbde90b3f1dec7fbb4c2e"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a6601550132597aa0d04ab201d4fa25001eadcad37853d76d9b28de1af3ba541d76911b603aa8a58f96e479b11c35119"
    $a1="a6601550132597aa0d04ab201d4fa25001eadcad37853d76d9b28de1af3ba541d76911b603aa8a58f96e479b11c35119"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ff3bd0b138f1d338f2561f1fa2f5ded9545fbb694cf41cc04e84e545"
    $a1="ff3bd0b138f1d338f2561f1fa2f5ded9545fbb694cf41cc04e84e545"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b7756d5573e5cb132c51a5dba920730ae147c15cd4dfa8c5c3366918b28d4af720be5a4defe425f7d495d482095a34159ee0eebcc55d7fc2e22858e319ed4c24"
    $a1="b7756d5573e5cb132c51a5dba920730ae147c15cd4dfa8c5c3366918b28d4af720be5a4defe425f7d495d482095a34159ee0eebcc55d7fc2e22858e319ed4c24"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2afcbb35be2ea74efb2a892c88269191243b9ae605729370f0018e9526674191"
    $a1="2afcbb35be2ea74efb2a892c88269191243b9ae605729370f0018e9526674191"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c59cf1d6caf5a2730e766d00726654168406338ad36c9a5a1b2d213c70758a682ca6add368afab42aac1845b262cd5122b069707856fe0f09786b67ec1e8c3a3"
    $a1="c59cf1d6caf5a2730e766d00726654168406338ad36c9a5a1b2d213c70758a682ca6add368afab42aac1845b262cd5122b069707856fe0f09786b67ec1e8c3a3"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e24e9b4cb59f40230fbb8e413691b07c06bee23070d58d64bcb12633d47e9602"
    $a1="e24e9b4cb59f40230fbb8e413691b07c06bee23070d58d64bcb12633d47e9602"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4c04d1b47aef7fbda64e3c28eea479c9c651fce610b1fbad5fe10dce"
    $a1="4c04d1b47aef7fbda64e3c28eea479c9c651fce610b1fbad5fe10dce"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a9afaab1fea11cae88ee931e7355253cb3fd60e0eecf1dcd31bf6bcf91bc361"
    $a1="2a9afaab1fea11cae88ee931e7355253cb3fd60e0eecf1dcd31bf6bcf91bc361"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d1d4fce6765938345877c69c3a1035062812d0d0a6be0e9d892c1093b165082a2624306e56eb863b239d842ff84c318f"
    $a1="d1d4fce6765938345877c69c3a1035062812d0d0a6be0e9d892c1093b165082a2624306e56eb863b239d842ff84c318f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="004fd741b37dff7b79b13c1737631970dff6fba29d668784017345d5d8d05f50c3a26d81102276eabf54d2588250f44f89ecd06e5c316de14748c350218af8bd"
    $a1="004fd741b37dff7b79b13c1737631970dff6fba29d668784017345d5d8d05f50c3a26d81102276eabf54d2588250f44f89ecd06e5c316de14748c350218af8bd"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_netgenesis
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for netgenesis. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bmFhZG1pbg=="
    $a1="bmFhZG1pbg=="
condition:
    ($a0 and $a1)
}


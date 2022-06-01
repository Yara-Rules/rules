/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7c9d6b001a87e497d6b96fbd4c6fdf51"
    $a1="7c9d6b001a87e497d6b96fbd4c6fdf51"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="23bb6aa6057b495b00a4cf076f54e2e03d786270"
    $a1="23bb6aa6057b495b00a4cf076f54e2e03d786270"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
    $a1="3ef2a64b67a399f73c1e5d12fdd259a2329ae2c6b403e432973b9c07c6f80be9238d940850535c30f74f254f037748cf"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
    $a1="d4fc2c43e8b403dd8b25f24b8dd85351fde69aa9f75efd1bc2bb3f47"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
    $a1="211b0236d991cc0a1eaa6f76fbb5f16fb3a828e943420ce003ecfca4309028697fcb47f55617bdd26b630a9b066d994f25854515ffa399ceb83a3cbeede4f8ce"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="db7fe17869dec0238836e15641f3236bc0c969dc822d251acc5ee469778cec3d"
    $a1="db7fe17869dec0238836e15641f3236bc0c969dc822d251acc5ee469778cec3d"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
    $a1="b17c17fed5e20da9907f5c22daf2de2310758bb78b2479dc3278abb045426f80f945ce64911abd789fe4e14e981b7e9f38e89f4458129723e5f0041d98d5e81c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e8db46948d8c0f796cb6029387db6f3d7c4b98019c91598a1211e1f5833edc46"
    $a1="e8db46948d8c0f796cb6029387db6f3d7c4b98019c91598a1211e1f5833edc46"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9aafdf73bbc88a244d14ae8cb81183133a9de1f7aa791eca79d8d1b8"
    $a1="9aafdf73bbc88a244d14ae8cb81183133a9de1f7aa791eca79d8d1b8"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
    $a1="864636fb9a29ce0369ab755c513affe71d3430404661f5be2d6f3f2cfe6283f5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
    $a1="8351f9f52ec352d4d182386e39ca40740290c6fe714b274d9f108764da5e722b40cd48de773a061c4ecffd6868558501"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
    $a1="f13ae629d2f18805bac5f213695962fa809736ce19af84dfb3370dc5c7bac5d39d076533c0d8d30a238d58cc250f680948a7c6728b5c7eb0ea68aaf4eeda2714"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_ssa
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for ssa. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="U1NB"
    $a1="U1NB"
condition:
    ($a0 and $a1)
}


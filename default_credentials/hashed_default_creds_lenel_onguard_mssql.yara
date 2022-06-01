/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a1234ca94b379cb927e767fe4bf67d2b"
    $a1="82956237dbf00a1884f3fc3bb970ae4f"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="881b198ee2b7e4e827edc4fe070392b943083514"
    $a1="4ba6d6a914f0b79191dd4934e626d8d8a5a96efa"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5f7c68c0b49811ae6114ab6ba14e2464d37918365fdfef4414fab738cc824bfbb09c085c688e4984972656215fc23965"
    $a1="5ce9a273f635c5e5a87de22eba5e797683d1e07b414fcf42e0e9d0e2cfe3378769f712bdc446d95c32b181c092aaef20"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0c2beec173564f1d010891c3ed175215e4129e3c059055547a4e87b1"
    $a1="c938aeac05dd353b9d6ca8099045020034515e4b06f50ec0569786a4"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2c43b432a31485229457525cfbd4af71c10d6a4e13c19e9c610f9b266be8feada0c201e57d60e0270a3b6a3d0a7d935ee4409ee4a74df73e086a0b05fda46363"
    $a1="9287cd7f4e78efc389baf282f685289a8b3943e5168af2dd3fa2a45f55eebc75d9c7f1148161f8916dcdd1d059bbcb13c7de7923aa8f13ed1c204da3654e7b45"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="62190838b03b0fbe2e01193bcadadf05fe4b5b26b4f5eedd52e38c0b480f1657"
    $a1="7f0a896345689429c31e318619f3b8e89de09a1505c2fc07f56ade9da047c9e5"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="600b2d139f6205822171838b01a909fa123d65719ed0748695f9129578d62798dd4977435a3435af18b9abaa2b201347a259659093c02bad254a7ceecd51877d"
    $a1="94bfc4b4c3b1fbc1c07701221d0fd293a111ab28970fb5609b093a245dbbf90b36f39153283230fcf08b8f9342378fb7784fd94cdfa85abc81812d32a7898c03"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9588bee56590a6531ff34fcfabc4c530b85d17a442b1347937cff4438e520cee"
    $a1="2e45e80b631b9023517089ea2ef621c68ff33438f6a7235537521407ce2af920"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="59350530052b856bf488a93df4a284d6e9e18b37d24d60b02e5e79d1"
    $a1="3e2e01fb78c2a92d5f462ce85ee9fd82858309f15049372e66d51b81"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b240f817fe65d6ee45fec36685b3b89406f8c40c51edcc3db3bc7eb3549667b8"
    $a1="be7c9134898fe9d6a3fb3a0aa5bfee620fa9d857826f3e3c71d133942d7fc4df"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4426c0a1df8e673fc52d7cd73daecd204aa2c1eb4d49315d4e37e2a4b6fde15472eddf535d38e3c5fc3e8498a58c5ba9"
    $a1="3d68cc4553d6275b12cafedfb75dea359b6e558d1294ea858bafff63a5eab5ddc48e97755cf9f19ee7f38ac8f76107f7"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2ec02fdad226ad835db9c2d6c6bff10f5918bedc5260f0cdb2f75cd8c11ddeacc7faaa256e478a728474f53273077d9e4f2afdae7624415d21e1e3911929c69"
    $a1="d376e80144053d1bf3fb9e9707a606c52cacd6633b9d27a124d50e0e7703427b4dbb5fbca7bdceb1a84bbcab769f17967ea0e1c7b68227003058a0e94d77698d"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_lenel_onguard_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for lenel_onguard_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="TEVORUw="
    $a1="TVVMVElNRURJQQ=="
condition:
    ($a0 and $a1)
}


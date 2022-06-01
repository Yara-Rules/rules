/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="dfeaf10390e560aea745ccba53e044ed"
    $a1="dfeaf10390e560aea745ccba53e044ed"
    $a2="744b41f0dccd32ebf5d525bc1c64af5a"
    $a3="dfeaf10390e560aea745ccba53e044ed"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a1="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
    $a2="998e7c5fcf168173985dc94f99a0373ec2b2df34"
    $a3="7af78c911d5b48bea1dc2449d9d89513abeb4be5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a1="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
    $a2="ebfcce5a94d625804ece72a70a1c36aeaba58bd2f034c9522e9c24a5dda030f66c106ff31255656c7bcb92c824c546da"
    $a3="3ace75c2597a98b4cd30615974d948d04c45108044d7340538736366249c454f6320f7c99a4f23649dc498c9eaa47977"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a1="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
    $a2="8eaa349e8a15c4dfa4c30fc6645740d51a69a9727aa77f28d1a8dbff"
    $a3="28de402a79abd7c5b3ee94f492b8f958c5f0d5044fef845d9f6aaacc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a1="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
    $a2="8fb64d78d481ac40eada3c93b77944e2c76d42e8419cbbf7f2aa2fa3ff1c167e51b908f5058bc7977da0afa68094494678ce2dcb343557a8446c7170215c2c42"
    $a3="ac853632a12ae128158fab24ce3a5472962826b026f1f43564a89d92af549ca77be6587381b637237387294dcbee069f8b3868fb2d2eae16c2f12a3412240fe5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a1="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
    $a2="57c712d37789c12225e9fa5c5af81338cfb2a7787cf84047d52d2b40fb73afb0"
    $a3="e73b79a0b10f8cdb6ac7dbe4c0a5e25776e1148784b86cf98f7d6719d472af69"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a1="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
    $a2="6f3d05b7c73920e4214486dbfa505555926e97baeccc530f509fbcb0ffc0b423d8a709d721fac41bb1c0ed365669f2430d0b8bdd16c462885bbad2d10275b396"
    $a3="86bf1a207cac134ce813d3c76492271f0322dfe2de8fdeefe541e08bd43dd628610ebbd57ae0c53eb931d6c9c27c11c32d3503d4552952d7808bc9d2d796d804"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a1="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
    $a2="2008ddb51e6f0e192c7ba137dbd27e689f59e6ce514c31d4912f58a32b7210a6"
    $a3="f54d3b4b69d81604529f3a1da472ec0d24530ac1d2b0f9230ff6a9bbca9d90af"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a1="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
    $a2="3e7cf6ccb212cddfe99cd22f7d64667033ef35354acead16cf9955ec"
    $a3="078af1b167057e4c232bc97bb9aa8f9600e559400374f78c74a9e842"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a1="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
    $a2="38ed6422dfe4b7c24ef3a3d98839028a140502cd003b88c28228907ae901a1b4"
    $a3="583f7adb4f102d74d3d0c5dbe590f7400fca4b8695c1e7ddfcc63da08831dc15"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a1="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
    $a2="71d64884648a064d2db9283ee86d2b83aeccc7b3f5365e528100d8aff72d5809cde102e9e3fc68dffc3a5cfd97226c9b"
    $a3="c42b311c9a806f1a08d98b449d28ee68e0e6b6121a3d040f12bc24401693c2915936ef1427013ed49b8a9af8f4af444b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a1="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
    $a2="02acdb33bfe258eb053a656c0faa07cd4792efc9a1875ff056154ee6c80823ed5200c7ea4f8f2e9f688179dc96eae2e0c6a010818286fabb7d263f3a4ff0784c"
    $a3="f0f2b4e8ae2b296dda4ac12b1f0d2d905d0951f93fec51796fd95f4bd866107a68e1e9c39450f6b077cac99cbf0b3818ecb43738b55975e14e2628e7e814430e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_cisco_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Y2lzY28="
    $a1="Y2lzY28="
    $a2="cGl4"
    $a3="Y2lzY28="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


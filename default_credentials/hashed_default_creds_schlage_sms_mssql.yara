/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c12e01f2a13ff5587e1e9e4aedb8242d"
    $a1="3b53c0fdf4273b55461084fc10fe2337"
    $a2="7429aa8563e64a38507552aa90fb331f"
    $a3="3b53c0fdf4273b55461084fc10fe2337"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a1="1133215157ff92cc61a17c4a6385e7e9c18e890f"
    $a2="4b6b362343a742ad40743f3e18e9770236076746"
    $a3="1133215157ff92cc61a17c4a6385e7e9c18e890f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4b7d79fd9e55caac33d50b5d5337899adc8be5e7a1c55446f514104a427cf9859c47284a663af817bd3b2478a578ea4e"
    $a1="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
    $a2="9bc3a99dd6aa1babf302dcacff9eba070607e7f92c51efc9826697547a32297b24744525528e243597edbb5aa0c3f346"
    $a3="ae958cc6b467f74d13d9b4223d48b7c22a513f85f1001c80ca5986040fe51d78662405653b08f0f53bbb39980a2840f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ba6ac6f77ccef0e3e048657cedd65a4089ecb6db72ff6957e1f69091"
    $a1="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
    $a2="8022ff7825f35bbeed2415087ac9899542a3ffe21a6084e16efe9bec"
    $a3="ef0a48857e59814ce0ec978f684b4580eeae835e84ed01df137e377f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30a76625d5fc75e3ab6793b19819935e65e43cf3745832061cb432a5de7fdc17d66ede77973d5aed065bc7e3e0536ebcc5129506955574e230b92b71bd2cb1c7"
    $a1="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
    $a2="7ccf8f59491f577b1405d4f1a6228d73eb7d45e67f156bf5459566307e72325a5318d85133c3078fa74cbaa04f5b0e92e681a09e3e3c87ba596e8d8005eaf0a4"
    $a3="4d479e13acbb40ee9b9038180f1953186a2ad22516b2b5ed6d8715a07db2bb465117547575d8415c6561c58d315949bf2b9afdeb9566049b2504281cb41874be"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4cf6829aa93728e8f3c97df913fb1bfa95fe5810e2933a05943f8312a98d9cf2"
    $a1="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
    $a2="043e98d3441cf2d70e089418ca866efc8b14c496f71c3ee6eca3e6113dd17d2c"
    $a3="264de172cfe8b910cc5e8eef630ff78cac224101f14a01cd3661f66044691eaa"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a1="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
    $a2="16d2d1ca296c5929e0f1129225cee04ced9671246a688e30fb0c8822ffcc4e594aa33630a80ff1c87d5d58d492c7730bf36190e21628c1e20400b095fdebce4b"
    $a3="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a08ae1b0def7ea98c217ccc1140f411909bc545e808e6629ee4511c72db5243a"
    $a1="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
    $a2="2a40a2d445c601b9ef86c2d92fd47b50b83c820a1776e4a745feaf941528119b"
    $a3="4247843133c0643f01f0994852c52ac076535a4b17dd62ad6450a3d6a80f63a1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cc8755b6c72eebaea22058348aadcbbf6b0c72deade2f1523875df71"
    $a1="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
    $a2="1f2b34adae97ba0be8aec562b00df7d82ba894326901788bc4ec25cf"
    $a3="e82d2968d2b62a52a50c3a4becb4adcb8d4f0a5c6e5aee14a01a68ed"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="665b3f32dcb321aa06ce5010ad9e9abb83d265e7e6dbc33b2fbbbfdbca0b8359"
    $a1="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
    $a2="e3af3655adf7db74a945a34e361f8fa2ccd791da8e4727c5b853c81fdc33f483"
    $a3="e398f3018ecedb0bcdb4e05ffdf78f2d98b0ca456680ea2eba89d424f3e388f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
    $a1="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
    $a2="f1489c225acb5ebe3c774772b80f34fb955dddc69a8c66f210e63eddc681aae0b3a5374624666a60cb41cd809d077c27"
    $a3="c9a9f1fe5c2f7e69c342bedb55caaa6d54303c596f89734b36fc7603602eb3f13b25db9d916ab415cc55e03c9f0453ac"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
    $a1="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
    $a2="6ff1755e0fecc408e984ac26c8776c950bb31a429eeda7ccff39770b77314d9aacd339854ca8a3dabc4b087e95f6b216421523e070bb0d02c77792f73a35ec3b"
    $a3="bba69ca5f704e7bbd4d798e059559d2dd07d6095f086e9b30a33635f08477e1d34f6a7dcd58eb79efda23b9f80cb6b1ceabca6e713a4021a45a938cdd552e8f3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_schlage_sms_mssql
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for schlage_sms_mssql. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c2E="
    $a1="U0VDQWRtaW4x"
    $a2="U01TQWRtaW4="
    $a3="U0VDQWRtaW4x"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7b1d1185b835814de783483f686e9825"
    $a1="7b1d1185b835814de783483f686e9825"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a23ff8784cfe3f858a07b2cdeb25cbd27aa99808"
    $a1="a23ff8784cfe3f858a07b2cdeb25cbd27aa99808"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aad60e1491e35b81089fb2a929c6b8fa5a1138295df2ac65fa3435a2986f20aadb2dd6b5302d62380290f51469462698"
    $a1="aad60e1491e35b81089fb2a929c6b8fa5a1138295df2ac65fa3435a2986f20aadb2dd6b5302d62380290f51469462698"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="583c1fba30662a7676f64a5359a398b10f66451525ae7d661feff14c"
    $a1="583c1fba30662a7676f64a5359a398b10f66451525ae7d661feff14c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="734577c6e2a923caee555c9b4699f15e1df4a32c6e68766cbca81f4c5fb710f79fda29e376e0ce7b139ec451b7de9075adf8b6b6cc0469ddab29c903fec9483e"
    $a1="734577c6e2a923caee555c9b4699f15e1df4a32c6e68766cbca81f4c5fb710f79fda29e376e0ce7b139ec451b7de9075adf8b6b6cc0469ddab29c903fec9483e"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="aa669b285cc133bf8440ce04e6c2559ed5ce8c77cab452d0152f0da9f3e21f89"
    $a1="aa669b285cc133bf8440ce04e6c2559ed5ce8c77cab452d0152f0da9f3e21f89"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="418452092fc0abac2681f8ef7d5a24aa48f54516fd6196097ba2a09bca5acf0548ee922a92ceae05c635adfbbfd7eeb354d8f46a8550af0194ae9ff9dfc6d401"
    $a1="418452092fc0abac2681f8ef7d5a24aa48f54516fd6196097ba2a09bca5acf0548ee922a92ceae05c635adfbbfd7eeb354d8f46a8550af0194ae9ff9dfc6d401"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bad09a0fcdb04bfbe31c7ecec2ece19776acabbd6261e6c34adfa0a538270198"
    $a1="bad09a0fcdb04bfbe31c7ecec2ece19776acabbd6261e6c34adfa0a538270198"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8d780e66f046d5a8c6e908838c3569d9938c0a1edd89a1fdc092e566"
    $a1="8d780e66f046d5a8c6e908838c3569d9938c0a1edd89a1fdc092e566"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0f724d076a5945970b669e7354859705fea71f98042e552fe46b4e8c4fc5fbca"
    $a1="0f724d076a5945970b669e7354859705fea71f98042e552fe46b4e8c4fc5fbca"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2272fa9f41e10bd326a5f9d2bb95ac423fb363465ab640fd442102c896c54784c53906fa961b613734e68dd76b92dc41"
    $a1="2272fa9f41e10bd326a5f9d2bb95ac423fb363465ab640fd442102c896c54784c53906fa961b613734e68dd76b92dc41"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5438403acc583e941b479bf65876dc3efc1c3c0d200568dfe7daaa7b023832f261e8165d17837a6af4c6f5dcda0b99f25b63c2ef29d46e6e6fa135f8770b0104"
    $a1="5438403acc583e941b479bf65876dc3efc1c3c0d200568dfe7daaa7b023832f261e8165d17837a6af4c6f5dcda0b99f25b63c2ef29d46e6e6fa135f8770b0104"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_cisco_aironet_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for cisco_aironet_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="Q2lzY28="
    $a1="Q2lzY28="
condition:
    ($a0 and $a1)
}


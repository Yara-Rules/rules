/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6ce6dcdf21de6a4bce879847e2346532"
    $a1="6ce6dcdf21de6a4bce879847e2346532"
    $a2="2cf79e8f137b5429d1c5a5351e00c5de"
    $a3="2cf79e8f137b5429d1c5a5351e00c5de"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="30588b8b7d4e67dca9e170004cf4bf1aab9f9b12"
    $a1="30588b8b7d4e67dca9e170004cf4bf1aab9f9b12"
    $a2="a005a2d3342a687ea2d05360c953107acbe83e08"
    $a3="a005a2d3342a687ea2d05360c953107acbe83e08"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="b9f6bcd3e7a2ebaa4dae2d3c768f5a3e2e69cca6e3e0dc48b9a40836810e97d866d4d99a22b630a58a7a8c4f12e416db"
    $a1="b9f6bcd3e7a2ebaa4dae2d3c768f5a3e2e69cca6e3e0dc48b9a40836810e97d866d4d99a22b630a58a7a8c4f12e416db"
    $a2="6a12c808653fd857c5076fd49bff500e03486d78eab8872c26c563d7f8ff12a200d7cd8f5453376100dc089f3e54ba16"
    $a3="6a12c808653fd857c5076fd49bff500e03486d78eab8872c26c563d7f8ff12a200d7cd8f5453376100dc089f3e54ba16"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8a7d3495f816beda79e2d039d3edf9a5d1fc1f639cd76519f933e0d1"
    $a1="8a7d3495f816beda79e2d039d3edf9a5d1fc1f639cd76519f933e0d1"
    $a2="78192940297071d6c4550252a25fb405928fce831b80c9740c01cfa9"
    $a3="78192940297071d6c4550252a25fb405928fce831b80c9740c01cfa9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1250811abed3d38fc35ae12c133d837bb3bf2df78b8941dfd0fc64c003899573dc3e44e4308ad1d80c6afd1af562b47a0d91f1fc515a7feb6b49ccf476f1d6b2"
    $a1="1250811abed3d38fc35ae12c133d837bb3bf2df78b8941dfd0fc64c003899573dc3e44e4308ad1d80c6afd1af562b47a0d91f1fc515a7feb6b49ccf476f1d6b2"
    $a2="7afcf71d8fb958b8140b7a5e0eef3aa44ebdab94a11180d7bf5ad63489bd4dfa1972af70875890aa01fe63fb0063be8aa6ed9853bfdc65e435853929b0993cb0"
    $a3="7afcf71d8fb958b8140b7a5e0eef3aa44ebdab94a11180d7bf5ad63489bd4dfa1972af70875890aa01fe63fb0063be8aa6ed9853bfdc65e435853929b0993cb0"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0228ba1c9fa00283cb17958ea7f601c602580fe4fa29bbb1c4c89ae4d2828cb8"
    $a1="0228ba1c9fa00283cb17958ea7f601c602580fe4fa29bbb1c4c89ae4d2828cb8"
    $a2="7b8c8ebdd4a28d34f1048da4e4916dbf0ed5771944805100ddf1b29c9509b6f6"
    $a3="7b8c8ebdd4a28d34f1048da4e4916dbf0ed5771944805100ddf1b29c9509b6f6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="191c46b7aa0d2f9ac3d5ec056d885ba4d0959a9a256b2f12da071cdef16fc990b9ebf1bd41a637b8af38dc453cc2a77270689e1bca2a1a2fc038e6e8a4d988f0"
    $a1="191c46b7aa0d2f9ac3d5ec056d885ba4d0959a9a256b2f12da071cdef16fc990b9ebf1bd41a637b8af38dc453cc2a77270689e1bca2a1a2fc038e6e8a4d988f0"
    $a2="43c36c46544ba3dd7db6c773aff52327e5fc434aae1ac05e0320b789d206aec12004f7a7675864e6aa15c5159c0b124ef2b0e0894327932effed6692f8aeaf65"
    $a3="43c36c46544ba3dd7db6c773aff52327e5fc434aae1ac05e0320b789d206aec12004f7a7675864e6aa15c5159c0b124ef2b0e0894327932effed6692f8aeaf65"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3753142fddf2d0205385bb5ce095d7a9965047701ab02115eaf8d4b970ee50f"
    $a1="e3753142fddf2d0205385bb5ce095d7a9965047701ab02115eaf8d4b970ee50f"
    $a2="90a0c24c1c32d0e35062d7f58c7a61e9d4ff21bc7f83b8a5fb4f690aa584b1ff"
    $a3="90a0c24c1c32d0e35062d7f58c7a61e9d4ff21bc7f83b8a5fb4f690aa584b1ff"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="470ece5bbfc1cb409a4899c3d9c2bbf16342a5331cff819e2d143fc4"
    $a1="470ece5bbfc1cb409a4899c3d9c2bbf16342a5331cff819e2d143fc4"
    $a2="5a1f82cb4122c4e4412620f0873b4dad93ec30732c0e3a135287dc71"
    $a3="5a1f82cb4122c4e4412620f0873b4dad93ec30732c0e3a135287dc71"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="71bc7d7523b4b6677a662b404a0d9645dd022942c1f43122beced8650fd8b86c"
    $a1="71bc7d7523b4b6677a662b404a0d9645dd022942c1f43122beced8650fd8b86c"
    $a2="1df8dc39904e7c2cc6cfaf6238503488557be3319aa790948ca068cf0946b2df"
    $a3="1df8dc39904e7c2cc6cfaf6238503488557be3319aa790948ca068cf0946b2df"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="117909d07776024d5bcc2c958d4e5d4f6de2425de9366f29e0d8819988b0ce1b1c5a7e7834ad1ec06d1cf515e3f8bf41"
    $a1="117909d07776024d5bcc2c958d4e5d4f6de2425de9366f29e0d8819988b0ce1b1c5a7e7834ad1ec06d1cf515e3f8bf41"
    $a2="1a57512c9cb0b1e7030c6d087f984997d0ae178d63170e2a9f1129e66feb2a202c09a1791bc0aa18f38898cd14da3c87"
    $a3="1a57512c9cb0b1e7030c6d087f984997d0ae178d63170e2a9f1129e66feb2a202c09a1791bc0aa18f38898cd14da3c87"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0a482141f68d8c26f44c3fd81248859a6298f549fb5ce47c1fe72662b6563a4bd853a7826f4869542c933b3dea4d178cecdf8795d23dbc85aa07b8e559a005a7"
    $a1="0a482141f68d8c26f44c3fd81248859a6298f549fb5ce47c1fe72662b6563a4bd853a7826f4869542c933b3dea4d178cecdf8795d23dbc85aa07b8e559a005a7"
    $a2="75d573a7edd57cff1449898f5ac72b14312651a7be4fd685997d450a0846ea7d0ec9df7aca6e769cd8a0cc97b044903c14c715e8ad1c72d43ad7741935cadcef"
    $a3="75d573a7edd57cff1449898f5ac72b14312651a7be4fd685997d450a0846ea7d0ec9df7aca6e769cd8a0cc97b044903c14c715e8ad1c72d43ad7741935cadcef"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_metasploit_ssh
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for metasploit_ssh. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bXNmZGV2"
    $a1="bXNmZGV2"
    $a2="bXNm"
    $a3="bXNm"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="99fedb09f0f5da90e577784e5f9fdc23"
    $a1="99fedb09f0f5da90e577784e5f9fdc23"
    $a2="293c9ea246ff9985dc6f62a650f78986"
    $a3="293c9ea246ff9985dc6f62a650f78986"
    $a4="4a05015d71f045770d4f59704146fe2d"
    $a5="4a05015d71f045770d4f59704146fe2d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a1="25c5d184fd3c8e7d24af0e237c061f5480a5e86e"
    $a2="f40b27d6b8b9a4fc3827264c1da16a04ecf4d094"
    $a3="f40b27d6b8b9a4fc3827264c1da16a04ecf4d094"
    $a4="37dc93df3b8a3da037e42cd0cb632352b36574ef"
    $a5="37dc93df3b8a3da037e42cd0cb632352b36574ef"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a1="eebd241a3d613fd87a4c30402fdd66b0667361380faafcfcb1bcc7e9c7029ca99137d974dd981b45ab947545bda0ec3d"
    $a2="fdbf2e4eadc2dff798403ceff70a4b86094144d0e4c5e73dcb01cef506bcb573e98c2e2c978660b605e8a78422251a0e"
    $a3="fdbf2e4eadc2dff798403ceff70a4b86094144d0e4c5e73dcb01cef506bcb573e98c2e2c978660b605e8a78422251a0e"
    $a4="e3fc98db1a3da1991bda5ba75b4d0627e1445715d860e6a274e6cea995ada45cf9e619e56a1d6270ab64e82312ca2958"
    $a5="e3fc98db1a3da1991bda5ba75b4d0627e1445715d860e6a274e6cea995ada45cf9e619e56a1d6270ab64e82312ca2958"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a1="10104dfcce0ff3c3301e0c0cd27abaa31c65dc9d0d2bbee6094ec8f6"
    $a2="c820f3b40c3efbfa79b45ed41fab1396728982b23aca5a64be2cadf0"
    $a3="c820f3b40c3efbfa79b45ed41fab1396728982b23aca5a64be2cadf0"
    $a4="ad1b07f41d112c11c5f55426149af9d6309318f989fc84ac44b34cae"
    $a5="ad1b07f41d112c11c5f55426149af9d6309318f989fc84ac44b34cae"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a1="22500de59d4c497fb66ef2fd70f31f8e64e37afe4bdd05d92650fc9464d852dfd0755783085ed762c474dc11ec35ce7df1ce8beb5767d3769a50ff5b6a88c5ba"
    $a2="81b64845be8c00c4092674cf00f085561fae4d9ab6c16f7bf48f0f1f4dd108db5d869ec2ef0a1e6c120ca2c7c33dccc41b4e542abf9e5c2cd24c9f517172151c"
    $a3="81b64845be8c00c4092674cf00f085561fae4d9ab6c16f7bf48f0f1f4dd108db5d869ec2ef0a1e6c120ca2c7c33dccc41b4e542abf9e5c2cd24c9f517172151c"
    $a4="7eadc0558bb685b60c9838275fe9ff9c4ef6e8945428b446f15f305fca7ab6d5308ece5bfcac25369aa0c98778b8d0d4b6e495a4ddf3dc42488060fb00c893d8"
    $a5="7eadc0558bb685b60c9838275fe9ff9c4ef6e8945428b446f15f305fca7ab6d5308ece5bfcac25369aa0c98778b8d0d4b6e495a4ddf3dc42488060fb00c893d8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a1="950dafb5e3c2b4511e9d93f7b24e143333173f67c67530ff318319ac13f62604"
    $a2="56d6f32151ad8474f40d7b939c2161ee2bbf10023f4af1dbb3e13260ebdc6342"
    $a3="56d6f32151ad8474f40d7b939c2161ee2bbf10023f4af1dbb3e13260ebdc6342"
    $a4="548b5bb8af2562d792042b9ba2bac5025de5f360b0e1d9d561c12bb5f1ff00be"
    $a5="548b5bb8af2562d792042b9ba2bac5025de5f360b0e1d9d561c12bb5f1ff00be"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a1="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a2="142cb3a983c6f7b0586e66f9f8e1f647ad59a143afe6acc09931abce078102cd11a282f23fbda39ded6b784985e2268528628e5ba35ebdc1aead6d04535e3eb4"
    $a3="142cb3a983c6f7b0586e66f9f8e1f647ad59a143afe6acc09931abce078102cd11a282f23fbda39ded6b784985e2268528628e5ba35ebdc1aead6d04535e3eb4"
    $a4="ed147631c18cfef980bed1125cee523643980c5843fa1d8efd954b2ef4fbbf0c3ad0160d02b5fec246d171959aa4e4e7ba6fe65dbe88283a806c2131411d9a21"
    $a5="ed147631c18cfef980bed1125cee523643980c5843fa1d8efd954b2ef4fbbf0c3ad0160d02b5fec246d171959aa4e4e7ba6fe65dbe88283a806c2131411d9a21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a1="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a2="f3683bf464195f998f521fe213497abe433d504f303e385624da0038137148b9"
    $a3="f3683bf464195f998f521fe213497abe433d504f303e385624da0038137148b9"
    $a4="8098327fb17813bd681a3a8353931abd66b3981a265bf43178396cc230868b03"
    $a5="8098327fb17813bd681a3a8353931abd66b3981a265bf43178396cc230868b03"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a1="ae1a28c805a9eb26696968a04bc804265aabeccc0011f39f5377aaaa"
    $a2="404e6d67fca63bda577d2592bf02fbd76d5658a29c2c5211bdadd16e"
    $a3="404e6d67fca63bda577d2592bf02fbd76d5658a29c2c5211bdadd16e"
    $a4="c2107b85dbf5b3b63a2f747a9a4e37aca34f254925b5b55fe5978876"
    $a5="c2107b85dbf5b3b63a2f747a9a4e37aca34f254925b5b55fe5978876"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a1="02dc26e7cc00505a831e2ef22e532835c313e0cc563080d7a758b1b98135bde0"
    $a2="8f2ae62f783a1c66d89c855ccf543a0d6d7bdd7aecac2faf6140b25c9477240b"
    $a3="8f2ae62f783a1c66d89c855ccf543a0d6d7bdd7aecac2faf6140b25c9477240b"
    $a4="7ddb640823a60533cb13ac0a9f15f88b79d32c274bee9e8821ed7e1333ad71cc"
    $a5="7ddb640823a60533cb13ac0a9f15f88b79d32c274bee9e8821ed7e1333ad71cc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a1="8354fd6700889606475262f1c2594921dc0cdeb891beb5bdf8e21a803bdc4c4e1bef774f86b30e6adbb5eeb0979a7d39"
    $a2="a695cbbc6ba7f0442f5acee0f756cd6057cfc50d1383fcec2507717b4a4346929cf5f8aa2b44e67d3bdaddbcacb04ece"
    $a3="a695cbbc6ba7f0442f5acee0f756cd6057cfc50d1383fcec2507717b4a4346929cf5f8aa2b44e67d3bdaddbcacb04ece"
    $a4="860253787ae9161f3b72e689582d2beaebc1cdfb521053f2ba12ad3db10ce677f2323171e205f82668d109d818bbf16a"
    $a5="860253787ae9161f3b72e689582d2beaebc1cdfb521053f2ba12ad3db10ce677f2323171e205f82668d109d818bbf16a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a1="03f70d78376b41fe748f5414954cf4cad830dd6ad583c2994b5ebb1bc12d2e028827fce6396bc4f6ab0d584f725748b30629468d87fe4bdd2a37bdf726300066"
    $a2="bf04400e21ef16275f0dd185ce0ae499ee0720017dcca34bb4bb526054e76087ab412be48573f84a1cf48a8f7e3bd71ba6008d44cb3b8f350ce4d7163cf5399d"
    $a3="bf04400e21ef16275f0dd185ce0ae499ee0720017dcca34bb4bb526054e76087ab412be48573f84a1cf48a8f7e3bd71ba6008d44cb3b8f350ce4d7163cf5399d"
    $a4="34b16275d8b2157ed28830f3b67135512125b2fc671299374182e50b00ce211f76840aa4451dd3b7364953873f20b04f13b5a0144a4103543aa0cf54d2e72c1d"
    $a5="34b16275d8b2157ed28830f3b67135512125b2fc671299374182e50b00ce211f76840aa4451dd3b7364953873f20b04f13b5a0144a4103543aa0cf54d2e72c1d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_unisys
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for unisys. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QURNSU5JU1RSQVRPUg=="
    $a1="QURNSU5JU1RSQVRPUg=="
    $a2="SFRUUA=="
    $a3="SFRUUA=="
    $a4="TkFV"
    $a5="TkFV"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="273910799eacaacec06aba83c9d54906"
    $a1="273910799eacaacec06aba83c9d54906"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="273910799eacaacec06aba83c9d54906"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f9965239005f50b3eee8d3c472b9ecf014ea8588"
    $a1="f9965239005f50b3eee8d3c472b9ecf014ea8588"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="f9965239005f50b3eee8d3c472b9ecf014ea8588"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
    $a1="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="1bca8ac0bacf8ec571da74c19880f4867d1c004064320586527cdb010743885ad0eee3c14a6d3a52bee52daf1d522c28"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2a96b837a48a64f49943b1d3ca809317bc4da293321cb2b7646ecd9d"
    $a1="2a96b837a48a64f49943b1d3ca809317bc4da293321cb2b7646ecd9d"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="2a96b837a48a64f49943b1d3ca809317bc4da293321cb2b7646ecd9d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
    $a1="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a49c1d0380688dd9e1898df37e8a7f9e7747212a5b47494173bd2e4a91452fb7"
    $a1="a49c1d0380688dd9e1898df37e8a7f9e7747212a5b47494173bd2e4a91452fb7"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="a49c1d0380688dd9e1898df37e8a7f9e7747212a5b47494173bd2e4a91452fb7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
    $a1="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="9fd584d5ee5f8eaaa7752760a588543316b3cce5e22a846eaeac765399ceff8a85eb610c78f1a48fd570d5f4371ffb8da382b75eae5e08e135a3fad21290a303"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
    $a1="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="cb90d090f2a324ae35246381bb86720a754b317213920f8f5e9bbfecf05c08c3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c42eb30bf2ef3cd857cf68e7bfec3042c832835f92eff9835c4d56ea"
    $a1="c42eb30bf2ef3cd857cf68e7bfec3042c832835f92eff9835c4d56ea"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="c42eb30bf2ef3cd857cf68e7bfec3042c832835f92eff9835c4d56ea"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
    $a1="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="0e6488141ddf1a37cc8222018eaca80dd0a6e281f8b82e7e86e2e2f4b575db77"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
    $a1="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="ad04782299d68313c5f458912cee951aa668825a891f11e1739e4895d8b9270c1c534866f090d9c8ecee8792b2724057"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
    $a1="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_alien_technology
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for alien_technology. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWxpZW4="
    $a1="YWxpZW4="
    $a2="cm9vdA=="
    $a3="YWxpZW4="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


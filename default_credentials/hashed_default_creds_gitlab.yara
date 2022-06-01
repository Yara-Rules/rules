/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="b88cf62b30ece438c1a194279b59bb2c"
    $a2="f7daa65b2aa96290bb47c4d68d11fe6a"
    $a3="b88cf62b30ece438c1a194279b59bb2c"
    $a4="63a9f0ea7bb98050796b649e85481845"
    $a5="b88cf62b30ece438c1a194279b59bb2c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a2="9993c0ee288292078ca1a18dad545a06622583f3"
    $a3="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a4="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a5="19f51d610c4dff3e3345b728162a03d057bc1ce1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a2="7a9bd2c97c0dac298d32249ecb1dbfa11a112206d1d4ca7019e8a949ee0b21ef5aa21fc1a6ace95894f0cac1bb1f9859"
    $a3="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a4="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a5="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
    $a2="14317ef3cef66033c1e77efbc868602a71e0a38fc7f160a850705edc"
    $a3="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
    $a4="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a5="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a2="45cb609b65c72bcd4b04bb464b4e8f607a494b266b875fc3dde1486c1c5353cf2c65d98b34cb2433b9a1e4c22dc73b257b8217a182a9185d6da0766fa9cebb93"
    $a3="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a4="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a5="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a2="2e93f8045553c109d586f91d54e4902ff14dc793562a9d2ac2ca5bb86bce6ed9"
    $a3="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a4="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a5="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a2="0b0fca99fb86bd76323cc883535114175ff2e168d2676daa85475d50b78ec20826ef815b47247f1f023d49377f263e541de87865163ea6961ab6a184fcd485b8"
    $a3="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a4="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a5="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a2="34f8088efcdb01c2ad09b5ddf0dab2db7815dcd85e41f470d6cd67643cfb7104"
    $a3="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a4="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a5="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
    $a2="49982d908e2ed611f052ab311b4362b62d60c9fe9b146ea6054965be"
    $a3="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
    $a4="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a5="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a2="a33d7fc424197e98a797d8ceb3cdfb47941e3f21d290ccaef47fe492130d9292"
    $a3="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a4="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a5="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a2="14b1914cf42ec57ecd7f56c7d6fc406cfbd67e5f1028f4e72bf1f665bbb359f60931835b2ba21ec2d6d6008d7fe7cb4f"
    $a3="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a4="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a5="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a2="468d495158f47cd4f838375dd4aa880dbeb244392e74f58a32d82d88d0574df1ece01af93b6e5458bc62796981d13a4d0097e4b45bbbd2b6236234e8168aa5c7"
    $a3="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a4="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a5="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_gitlab
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for gitlab. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="YWRtaW4="
    $a1="NWl2ZUwhZmU="
    $a2="YWRtaW5AbG9jYWwuaG9zdA=="
    $a3="NWl2ZUwhZmU="
    $a4="cm9vdA=="
    $a5="NWl2ZUwhZmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}


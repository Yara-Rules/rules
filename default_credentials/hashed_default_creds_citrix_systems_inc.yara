/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="159851f6cd03c82bba2455db23859959"
    $a1="159851f6cd03c82bba2455db23859959"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="cd92a26534dba48cd785cdcc0b3e6bd1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="43f3a9b7422c49256446f8f54cd1540a5cb566b9"
    $a1="43f3a9b7422c49256446f8f54cd1540a5cb566b9"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="1a935314579adfe8dc18db6ae1e8aec4df941a93"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a1="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="c8e4be78953b879b1ad771fbc1fb080dfbbdd939ddc1829eb84d1a02bd2f1531b63ab70ec8b37edc6d3107e78157387a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="ed339d5347bb8c7d342b3f9802521583da728cbe057e835242d9183a"
    $a1="ed339d5347bb8c7d342b3f9802521583da728cbe057e835242d9183a"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="9132ec183bfa4ac985230f71f349d6864935ce6dc02d808a697886a6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a1="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="8fa46b8c73e1d37a5c0caeb40bbd4fec341988ffe54af0996ff59929b49fd88246f2c650c0e5e5ae8a55f1771a4c22aca3dfd06ead066318ae33cd893aaccae1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a1="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="799824ba3560d3955f302c392de50e2232991ffaeca6f24200cf46571b523489"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a1="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="d651a36187b6d01a9812213aa56682d60e1895af80b9f596d1e7167139a4c66564a1fd35fa236312ab6a961353456e6953b3409da643b384192b3156e75ee37a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a1="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="135184fa03c0249f93e3c035457f986f887f294798f57efb63ff46391264cfa6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4cd430d5d60608b6185efd719ea4efe025da091cdc0cd318455c9e7b"
    $a1="4cd430d5d60608b6185efd719ea4efe025da091cdc0cd318455c9e7b"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="2d7977d8fd31d546485017eb23167a05cf59158ef4cd41100674f685"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="fecb449b8522288bc1c594c0198296ff5a40238927f24ceed09a30ec3ca70b15"
    $a1="fecb449b8522288bc1c594c0198296ff5a40238927f24ceed09a30ec3ca70b15"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="b3ba2f1db8eefecca5a701886790253b5cd6d23bf6533b8d070e1663282cccf2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a1="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="6f43dcbffa37b4eb4769c3ff6461afb8a8b8e20a3fc49f8741a0ef3a563eef3456886461cfff76a5fd0735f80888c9eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a1="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="5c28fa545a9f51d21f4ef7278184dc7e7809a64d9e9a19c98a6498480c38ea499828aa6553a6d8bf6c4dd82c9a72a19f45cc83b164860585c7facd622510561f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_citrix_systems_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for citrix_systems_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="bnNyb290"
    $a1="bnNyb290"
    $a2="cm9vdA=="
    $a3="cm9vdGFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}


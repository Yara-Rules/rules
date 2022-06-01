/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule md5_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="cfeffc883de264920b8277d4aea0cb05"
    $a1="1b9cee84c15cc60232c28f5806a66921"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="7e96f2a7c503f7a930dcf714ff4d1fc3f04b224a"
    $a1="41afd8a85a8be450810b4a29662c06494c2a1944"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="42f7b954c8874b30eef25102ac15541be58c278ae7679530773268ad7f5ee463da66ab0e7df4e2a84bf983bba379301b"
    $a1="5fe0f1c1f055bc4a34bd4580790d33fca2b1d00e4438acabd4714ead24133d8bc9eef9bbc3076a7ba7c77a8d4de24798"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="28bc2e0fb73036a9359aff9973e736bea374a4e0b7c860406a321f53"
    $a1="96ec15c20b94b215ae03e71e587dc513fa04a3e71ea5d1c93d287a1c"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="8e0a8fb22f8975d4dfc02e802e431cc896e30adc4c4d9e46efe87584c6a33028a6ab1ed219095afbb8f5e7117dcc469d7625499c270dee6e84a4b2dee9247d38"
    $a1="e8ced854720eb556137b52043ce832da9b04a4a6290521e890afb8148d16a16a4af2be315cadfa322b78b7a18d97285145dfbae9a26a8acea0a05d2fa5fab6cf"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="131550bc4081fa8ecfd8a479538d251b065d3d3e6915804b00797355437127ff"
    $a1="6e98045372e543c57672d4e4216e523d3b4b25ae4911cb03a9aef2674d893138"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="2da66a5a9b5134c7239c12e0b783c54eaaa343592cbefe13d8591baee600f072ddf2be2f6bbe8089e6b81427df48f5b7c95c68df3f4e81dc68fa23fe5fb365c2"
    $a1="d504d6aa3f0eca36bcaedebedc9f0bbfa2fba4de93fb9d4d6398719cb26797bf27d3abcfc3784db32030e040e1cece7d0d3fd3ed2796bb4651293584db4b8fd2"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="d2c7dc2ad84ac92c982b94d59933102631ad89a3075f3884568cce04cb27a2d2"
    $a1="c14520c08e20f8aa5c6cdf93744a23c16862ef29ac30e2238d29489995471469"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="394251e18514267b77adcafab473cc4bac76893cc07a14f4d578a770"
    $a1="dcd9a1d151c3cfc3a412e2cdd20185e5d6a8803fe0321cc764968d8b"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="34b13d6fbe184bd3b3c82c4eca056c9345636e642f407bc4cdf8268c702e773e"
    $a1="be66ee35e1792556c669b392bd7c601041eddc42c3aa73e4150c37a05a1bf782"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="e7fb2a9eff4df6b9e48aa3fbab461620eef6d53485fb5de58e85a635e676daa2c3c8b130180ee31b86a9a386145d793b"
    $a1="7a9c66e3498d6087d22d81b9ec38402d0b68ed4abea68105ee276ca59d9eea6c575a0d50976e5949f819041c82895946"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="6a44eada586fd0787145c2f11b77da92630761612222524a2618dcfc10ea80f163ae71add99eea26db0d06b3123641263fd9dc95f146fae71afbe8615db31657"
    $a1="763b7c9572ba528fb4626d620da16eef5a531293bf436aada2b6499d19d4ebbb31f156ac7ecb739664d4b53dc9888a98ee0285741280a9db9d411a686773d170"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_groupee_inc
{
meta:
    Version="0.1"
    Author="Alaa Jubakhanji"
    Notes="https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"
    Organization="ndaal Gesellschaft für Sicherheit in der Informationstechnik mbH & Co KG, Mathias-Brüggen-Str. 160, D 50829 Cologne, Germany, www.ndaal.eu"
    Description="Hashed values of default credentials for groupee_inc. Credentials available on https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/blob/main/DefaultCreds-Cheat-Sheet.csv"
strings:
    $a0="QWRtaW41"
    $a1="NHR1Z2JvYXQ="
condition:
    ($a0 and $a1)
}


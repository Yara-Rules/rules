/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/


// These rules have room for false positives if e.g. a dual use tool is contained within a hack tool repo.
// Could also be done with https://yara.readthedocs.io/en/stable/modules/dotnet.html#c.typelib but that needs an extra module.


rule HKTL_NET_GUID_CSharpSetThreadContext {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/CSharpSetThreadContext"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a1e28c8c-b3bd-44de-85b9-8aa7c18a714d" ascii nocase wide
        $typelibguid1 = "87c5970e-0c77-4182-afe2-3fe96f785ebb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ihack4falafel/DLL-Injection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3d7e1433-f81a-428a-934f-7cc7fcf1149d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeUSB_Csharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeUSB-Csharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "94ea43ab-7878-4048-a64e-2b21b3b4366d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Ladon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/Ladon"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c335405f-5df2-4c7d-9b53-d65adfbed412" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WhiteListEvasion {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/khr0x40sh/WhiteListEvasion"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "858386df-4656-4a1e-94b7-47f6aa555658" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Downloader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ec7afd4c-fbc4-47c1-99aa-6ebb05094173" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/K1ngSoul/DarkEye"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0bdb9c65-14ed-4205-ab0c-ea2151866a7f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpKatz"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8568b4c1-2940-4f6c-bf4e-4383ef268be9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ryhanson/ExternalC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7266acbb-b10d-4873-9b99-12d2043b1d4e" ascii nocase wide
        $typelibguid1 = "5d9515d0-df67-40ed-a6b2-6619620ef0ef" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Povlsomware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/povlteksttv/Povlsomware"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe0d5aa7-538f-42f6-9ece-b141560f7781" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunShellcode {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zerosum0x0/RunShellcode"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ec18a3-674c-4131-a7f5-acbed034b819" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLoginPrompt {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpLoginPrompt"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c12e69cd-78a0-4960-af7e-88cbd794af97" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Adamantium_Thief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Adamantium-Thief"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6104bc9-fea9-4ee9-b919-28156c1f2ede" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PSByPassCLM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/PSByPassCLM"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46034038-0113-4d75-81fd-eb3b483f2662" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_physmem2profit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/physmem2profit"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "814708c9-2320-42d2-a45f-31e42da06a94" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoAmci {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/NoAmci"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "352e80ec-72a5-4aa6-aabe-4f9a20393e8e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBlock {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SharpBlock"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3cf25e04-27e4-4d19-945e-dadc37c81152" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_nopowershell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/nopowershell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "555ad0ac-1fdb-4016-8257-170a74cb2f55" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LimeLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/LimeLogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "068d14ef-f0a1-4f9d-8e27-58b4317830c6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AggressorScripts {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/harleyQu1nn/AggressorScripts"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "afd1ff09-2632-4087-a30c-43591f32e4e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Gopher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/Gopher"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b5152683-2514-49ce-9aca-1bc43df1e234" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AVIator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Ch0pin/AVIator"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4885a4a3-4dfa-486c-b378-ae94a221661a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xPh0enix/njCrypter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a87b003-4b43-467b-a509-0c8be05bf5a5" ascii nocase wide
        $typelibguid1 = "80b13bff-24a5-4193-8e51-c62a414060ec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMiniDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpMiniDump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6ffccf81-6c3c-4d3f-b15f-35a86d0b497f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CinaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/wearelegal/CinaRAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8586f5b1-2ef4-4f35-bd45-c6206fdc0ebc" ascii nocase wide
        $typelibguid1 = "fe184ab5-f153-4179-9bf5-50523987cf1f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ToxicEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/ToxicEye"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1bcfe538-14f4-4beb-9a3f-3f9472794902" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Disable_Windows_Defender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Disable-Windows-Defender"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "501e3fdc-575d-492e-90bc-703fb6280ee2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dtrizna/DInvoke_PoC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5a869ab2-291a-49e6-a1b7-0d0f051bef0e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/chango77747/ReverseShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "980109e4-c988-47f9-b2b3-88d63fababdc" ascii nocase wide
        $typelibguid1 = "8abe8da1-457e-4933-a40d-0958c8925985" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SharpC2/SharpC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "62b9ee4f-1436-4098-9bc1-dd61b42d8b81" ascii nocase wide
        $typelibguid1 = "d2f17a91-eb2d-4373-90bf-a26e46c68f76" ascii nocase wide
        $typelibguid2 = "a9db9fcc-7502-42cd-81ec-3cd66f511346" ascii nocase wide
        $typelibguid3 = "ca6cc2ee-75fd-4f00-b687-917fa55a4fae" ascii nocase wide
        $typelibguid4 = "a1167b68-446b-4c0c-a8b8-2a7278b67511" ascii nocase wide
        $typelibguid5 = "4d8c2a88-1da5-4abe-8995-6606473d7cf1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HackingThings/SneakyExec"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "612590aa-af68-41e6-8ce2-e831f7fe4ccc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UrbanBishopLocal {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/UrbanBishopLocal"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "88b8515e-a0e8-4208-a9a0-34b01d7ba533" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cobbr/SharpShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bdba47c5-e823-4404-91d0-7f6561279525" ascii nocase wide
        $typelibguid1 = "b84548dc-d926-4b39-8293-fa0bdef34d49" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilWMIProvider {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sunnyc7/EvilWMIProvider"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a4020626-f1ec-4012-8b17-a2c8a0204a4b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GadgetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/med0x2e/GadgetToJScript"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "af9c62a1-f8d2-4be0-b019-0a7873e81ea9" ascii nocase wide
        $typelibguid1 = "b2b3adb0-1669-4b94-86cb-6dd682ddbea3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AzureCLI_Extractor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0x09AL/AzureCLI-Extractor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a73cad74-f8d6-43e6-9a4c-b87832cdeace" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_Escaper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/UAC-Escaper"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "95359279-5cfa-46f6-b400-e80542a7336a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HTTPSBeaconShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/limbenjamin/HTTPSBeaconShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aca853dc-9e74-4175-8170-e85372d5f2a9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AmsiScanBufferBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/AmsiScanBufferBypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "431ef2d9-5cca-41d3-87ba-c7f5e4582dd2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellcodeLoader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hzllaga/ShellcodeLoader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a48fe0e1-30de-46a6-985a-3f2de3c8ac96" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeystrokeAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii nocase wide
        $typelibguid1 = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellCodeRunner {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/antman1p/ShellCodeRunner"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "634874b7-bf85-400c-82f0-7f3b4659549a" ascii nocase wide
        $typelibguid1 = "2f9c3053-077f-45f2-b207-87c3c7b8f054" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensiveCSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/diljith369/OffensiveCSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c3fbc65-b673-40f0-b1ac-20636df01a85" ascii nocase wide
        $typelibguid1 = "2bad9d69-ada9-4f1e-b838-9567e1503e93" ascii nocase wide
        $typelibguid2 = "512015de-a70f-4887-8eae-e500fd2898ab" ascii nocase wide
        $typelibguid3 = "1ee4188c-24ac-4478-b892-36b1029a13b3" ascii nocase wide
        $typelibguid4 = "5c6b7361-f9ab-41dc-bfa0-ed5d4b0032a8" ascii nocase wide
        $typelibguid5 = "048a6559-d4d3-4ad8-af0f-b7f72b212e90" ascii nocase wide
        $typelibguid6 = "3412fbe9-19d3-41d8-9ad2-6461fcb394dc" ascii nocase wide
        $typelibguid7 = "9ea4e0dc-9723-4d93-85bb-a4fcab0ad210" ascii nocase wide
        $typelibguid8 = "6d2b239c-ba1e-43ec-8334-d67d52b77181" ascii nocase wide
        $typelibguid9 = "42e8b9e1-0cf4-46ae-b573-9d0563e41238" ascii nocase wide
        $typelibguid10 = "0d15e0e3-bcfd-4a85-adcd-0e751dab4dd6" ascii nocase wide
        $typelibguid11 = "644dfd1a-fda5-4948-83c2-8d3b5eda143a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SHAPESHIFTER {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/matterpreter/SHAPESHIFTER"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a3ddfcaa-66e7-44fd-ad48-9d80d1651228" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Evasor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cyberark/Evasor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1c8849ef-ad09-4727-bf81-1f777bd1aef8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stracciatella {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mgeeky/Stracciatella"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "eaafa0ac-e464-4fc4-9713-48aa9a6716fb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_logger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xxczaki/logger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9e92a883-3c8b-4572-a73e-bb3e61cfdc16" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Internal_Monologue {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/eladshamir/Internal-Monologue"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0c0333db-8f00-4b68-b1db-18a9cacc1486" ascii nocase wide
        $typelibguid1 = "84701ace-c584-4886-a3cf-76c57f6e801a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_GRAT2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/GRAT2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5e7fce78-1977-444f-a18e-987d708a2cff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerShdll {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/PowerShdll"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36ebf9aa-2f37-4f1d-a2f1-f2a45deeaf21" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CsharpAmsiBypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WayneJLee/CsharpAmsiBypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4ab3b95d-373c-4197-8ee3-fe0fa66ca122" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HastySeries {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/obscuritylabs/HastySeries"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8435531d-675c-4270-85bf-60db7653bcf6" ascii nocase wide
        $typelibguid1 = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii nocase wide
        $typelibguid2 = "300c7489-a05f-4035-8826-261fa449dd96" ascii nocase wide
        $typelibguid3 = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii nocase wide
        $typelibguid4 = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii nocase wide
        $typelibguid5 = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii nocase wide
        $typelibguid6 = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii nocase wide
        $typelibguid7 = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii nocase wide
        $typelibguid8 = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii nocase wide
        $typelibguid9 = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DreamProtectorFree {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Paskowsky/DreamProtectorFree"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f7e8a902-2378-426a-bfa5-6b14c4b40aa3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RedSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/RedSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "30b2e0cf-34dd-4614-a5ca-6578fb684aea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ESC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NetSPI/ESC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "06260ce5-61f4-4b81-ad83-7d01c3b37921" ascii nocase wide
        $typelibguid1 = "87fc7ede-4dae-4f00-ac77-9c40803e8248" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Csharp_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Csharp-Loader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5fd7f9fc-0618-4dde-a6a0-9faefe96c8a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_bantam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/gellin/bantam"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "14c79bda-2ce6-424d-bd49-4f8d68630b7b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpTask {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpTask"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "13e90a4d-bf7a-4d5a-9979-8b113e3166be" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsPlague {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RITRedteam/WindowsPlague"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "cdf8b024-70c9-413a-ade3-846a43845e99" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Misc_CSharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/Misc-CSharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii nocase wide
        $typelibguid1 = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSpray"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Obfuscator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Obfuscator"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8fe5b811-a2cb-417f-af93-6a3cf6650af1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SafetyKatz {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SafetyKatz"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8347e81b-89fc-42a9-b22c-f59a6a572dec" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Dropless_Malware {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Dropless-Malware"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "23b739f7-2355-491e-a7cd-a8485d39d6d6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UAC_SilentClean {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/EncodeGroup/UAC-SilentClean"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "948152a4-a4a1-4260-a224-204255bfee72" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DesktopGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/DesktopGrabber"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "e6aa0cd5-9537-47a0-8c85-1fbe284a4380" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_wsManager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guillaC/wsManager"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9480809e-5472-44f3-b076-dcdf7379e766" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UglyEXe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fashionproof/UglyEXe"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "233de44b-4ec1-475d-a7d6-16da48d6fc8d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "79c9bba3-a0ea-431c-866c-77004802d8a0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EducationalRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/EducationalRAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8a18fbcf-8cac-482d-8ab7-08a44f0e278e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealth_Kid_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ctsecurity/Stealth-Kid-RAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "bf43cd33-c259-4711-8a0e-1a5c6c13811d" ascii nocase wide
        $typelibguid1 = "e5b9df9b-a9e4-4754-8731-efc4e2667d88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCradle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpCradle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f70d2b71-4aae-4b24-9dae-55bc819c78bb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cnsimo/BypassUAC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4e7c140d-bcc4-4b15-8c11-adb4e54cc39a" ascii nocase wide
        $typelibguid1 = "cec553a7-1370-4bbc-9aae-b2f5dbde32b0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_hanzoInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P0cL4bs/hanzoInjection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "32e22e25-b033-4d98-a0b3-3d2c3850f06c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_clr_meterpreter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/OJ/clr-meterpreter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6840b249-1a0e-433b-be79-a927696ea4b3" ascii nocase wide
        $typelibguid1 = "67c09d37-ac18-4f15-8dd6-b5da721c0df6" ascii nocase wide
        $typelibguid2 = "e05d0deb-d724-4448-8c4c-53d6a8e670f3" ascii nocase wide
        $typelibguid3 = "c3cc72bf-62a2-4034-af66-e66da73e425d" ascii nocase wide
        $typelibguid4 = "7ace3762-d8e1-4969-a5a0-dcaf7b18164e" ascii nocase wide
        $typelibguid5 = "3296e4a3-94b5-4232-b423-44f4c7421cb3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BYTAGE {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/KNIF/BYTAGE"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8e46ba56-e877-4dec-be1e-394cb1b5b9de" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MultiOS_ReverseShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/belane/MultiOS_ReverseShell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "df0dd7a1-9f6b-4b0f-801e-e17e73b0801d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HideFromAMSI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0r13lc0ch4v1/HideFromAMSI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "b91d2d44-794c-49b8-8a75-2fbec3fe3fe3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetAVBypass_Master {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/lockfale/DotNetAVBypass-Master"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4854c8dc-82b0-4162-86e0-a5bbcbc10240" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDPAPI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpDPAPI"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "5f026c27-f8e6-4052-b231-8451c6a73838" ascii nocase wide
        $typelibguid1 = "2f00a05b-263d-4fcc-846b-da82bd684603" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Telegra_Csharp_C2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/sf197/Telegra_Csharp_C2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1d79fabc-2ba2-4604-a4b6-045027340c85" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCompile {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/SharpCompile"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "63f81b73-ff18-4a36-b095-fdcb4776da4c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Carbuncle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Carbuncle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3f239b73-88ae-413b-b8c8-c01a35a0d92e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OSSFileTool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/B1eed/OSSFileTool"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "207aca5d-dcd6-41fb-8465-58b39efcde8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Rubeus {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/Rubeus"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "658c8b7f-3664-4a95-9572-a3e5871dfc06" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Simple_Loader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cribdragg3r/Simple-Loader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Minidump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/3xpl01tc0d3r/Minidump"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "15c241aa-e73c-4b38-9489-9a344ac268a3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBypassUAC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FatRodzianko/SharpBypassUAC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0d588c86-c680-4b0d-9aed-418f1bb94255" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Lexus89/SharpPack"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid1 = "b59c7741-d522-4a41-bf4d-9badddebb84a" ascii nocase wide
        $typelibguid2 = "fd6bdf7a-fef4-4b28-9027-5bf750f08048" ascii nocase wide
        $typelibguid3 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
        $typelibguid5 = "f3037587-1a3b-41f1-aa71-b026efdb2a82" ascii nocase wide
        $typelibguid6 = "41a90a6a-f9ed-4a2f-8448-d544ec1fd753" ascii nocase wide
        $typelibguid7 = "3787435b-8352-4bd8-a1c6-e5a1b73921f4" ascii nocase wide
        $typelibguid8 = "fdd654f5-5c54-4d93-bf8e-faf11b00e3e9" ascii nocase wide
        $typelibguid9 = "aec32155-d589-4150-8fe7-2900df4554c8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Salsa_tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Hackplayers/Salsa-tools"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "276004bb-5200-4381-843c-934e4c385b66" ascii nocase wide
        $typelibguid1 = "cfcbf7b6-1c69-4b1f-8651-6bdb4b55f6b9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsDefender_Payload_Downloader {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/notkohlrexo/WindowsDefender-Payload-Downloader"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2f8b4d26-7620-4e11-b296-bc46eba3adfc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Privilege_Escalation {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/Privilege_Escalation"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ed54b904-5645-4830-8e68-52fd9ecbb2eb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Marauder {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/maraudershell/Marauder"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fff0a9a3-dfd4-402b-a251-6046d765ad78" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AV_Evasion_Tool {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/1y0n/AV_Evasion_Tool"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1937ee16-57d7-4a5f-88f4-024244f19dc6" ascii nocase wide
        $typelibguid1 = "7898617d-08d2-4297-adfe-5edd5c1b828b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Fenrir {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Fenrir"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "aecec195-f143-4d02-b946-df0e1433bd2e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StormKitty {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/StormKitty"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "a16abbb4-985b-4db2-a80c-21268b26c73d" ascii nocase wide
        $typelibguid1 = "98075331-1f86-48c8-ae29-29da39a8f98b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RunAsUser {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/atthacks/RunAsUser"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9dff282c-93b9-4063-bf8a-b6798371d35a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HWIDbypass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/yunseok/HWIDbypass"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "47e08791-d124-4746-bc50-24bd1ee719a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_XORedReflectiveDLL {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/XORedReflectiveDLL"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c0e49392-04e3-4abb-b931-5202e0eb4c73" ascii nocase wide
        $typelibguid1 = "30eef7d6-cee8-490b-829f-082041bc3141" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_Suite {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Sharp-Suite"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii nocase wide
        $typelibguid1 = "5611236e-2557-45b8-be29-5d1f074d199e" ascii nocase wide
        $typelibguid2 = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii nocase wide
        $typelibguid3 = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii nocase wide
        $typelibguid4 = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii nocase wide
        $typelibguid5 = "a5f883ce-1f96-4456-bb35-40229191420c" ascii nocase wide
        $typelibguid6 = "28978103-d90d-4618-b22e-222727f40313" ascii nocase wide
        $typelibguid7 = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii nocase wide
        $typelibguid8 = "414187db-5feb-43e5-a383-caa48b5395f1" ascii nocase wide
        $typelibguid9 = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii nocase wide
        $typelibguid10 = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii nocase wide
        $typelibguid11 = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii nocase wide
        $typelibguid12 = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii nocase wide
        $typelibguid13 = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii nocase wide
        $typelibguid14 = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii nocase wide
        $typelibguid15 = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rat_shell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/stphivos/rat-shell"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7a15f8f6-6ce2-4ca4-919d-2056b70cc76a" ascii nocase wide
        $typelibguid1 = "1659d65d-93a8-4bae-97d5-66d738fc6f6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_dotnet_gargoyle {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/countercept/dotnet-gargoyle"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76435f79-f8af-4d74-8df5-d598a551b895" ascii nocase wide
        $typelibguid1 = "5a3fc840-5432-4925-b5bc-abc536429cb5" ascii nocase wide
        $typelibguid2 = "6f0bbb2a-e200-4d76-b8fa-f93c801ac220" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_aresskit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/aresskit"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8dca0e42-f767-411d-9704-ae0ba4a44ae8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DLL_Injector {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tmthrgd/DLL-Injector"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4581a449-7d20-4c59-8da2-7fd830f1fd5e" ascii nocase wide
        $typelibguid1 = "05f4b238-25ce-40dc-a890-d5bbb8642ee4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TruffleSnout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/dsnezhkov/TruffleSnout"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "33842d77-bce3-4ee8-9ee2-9769898bb429" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Anti_Analysis {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Anti-Analysis"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3092c8df-e9e4-4b75-b78e-f81a0058a635" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BackNet {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/valsov/BackNet"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9fdae122-cd1e-467d-a6fa-a98c26e76348" ascii nocase wide
        $typelibguid1 = "243c279e-33a6-46a1-beab-2864cc7a499f" ascii nocase wide
        $typelibguid2 = "a7301384-7354-47fd-a4c5-65b74e0bbb46" ascii nocase wide
        $typelibguid3 = "982dc5b6-1123-428a-83dd-d212490c859f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AllTheThings {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/johnjohnsp1/AllTheThings"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "0547ff40-5255-42a2-beb7-2ff0dbf7d3ba" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AddReferenceDotRedTeam {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ceramicskate0/AddReferenceDotRedTeam"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "73c79d7e-17d4-46c9-be5a-ecef65b924e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Crypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Crypter"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f93c99ed-28c9-48c5-bb90-dd98f18285a6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserGhost {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/BrowserGhost"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2133c634-4139-466e-8983-9a23ec99e01b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tothi/SharpShot"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "057aef75-861b-4e4b-a372-cfbd8322c8e1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Offensive__NET {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mrjamiebowman/Offensive-.NET"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "11fe5fae-b7c1-484a-b162-d5578a802c9c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RuralBishop {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/RuralBishop"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe4414d9-1d7e-4eeb-b781-d278fe7a5619" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DeviceGuardBypasses {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DeviceGuardBypasses"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "f318466d-d310-49ad-a967-67efbba29898" ascii nocase wide
        $typelibguid1 = "3705800f-1424-465b-937d-586e3a622a4f" ascii nocase wide
        $typelibguid2 = "256607c2-4126-4272-a2fa-a1ffc0a734f0" ascii nocase wide
        $typelibguid3 = "4e6ceea1-f266-401c-b832-f91432d46f42" ascii nocase wide
        $typelibguid4 = "1e6e9b03-dd5f-4047-b386-af7a7904f884" ascii nocase wide
        $typelibguid5 = "d85e3601-0421-4efa-a479-f3370c0498fd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AMSI_Handler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/AMSI_Handler"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d829426c-986c-40a4-8ee2-58d14e090ef2" ascii nocase wide
        $typelibguid1 = "86652418-5605-43fd-98b5-859828b072be" ascii nocase wide
        $typelibguid2 = "1043649f-18e1-41c4-ae8d-ac4d9a86c2fc" ascii nocase wide
        $typelibguid3 = "1d920b03-c537-4659-9a8c-09fb1d615e98" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RAT_TelegramSpyBot {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TheHackToolBoxTeek {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii nocase wide
        $typelibguid1 = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii nocase wide
        $typelibguid2 = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii nocase wide
        $typelibguid3 = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii nocase wide
        $typelibguid4 = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii nocase wide
        $typelibguid5 = "295655e8-2348-4700-9ebc-aa57df54887e" ascii nocase wide
        $typelibguid6 = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_USBTrojan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mashed-potatoes/USBTrojan"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "4eee900e-adc5-46a7-8d7d-873fd6aea83e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_IIS_backdoor {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/WBGlIl/IIS_backdoor"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "3fda4aa9-6fc1-473f-9048-7edc058c4f65" ascii nocase wide
        $typelibguid1 = "73ca4159-5d13-4a27-8965-d50c41ab203c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ShellGen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/ShellGen"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "c6894882-d29d-4ae1-aeb7-7d0a9b915013" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mass_RAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Mass-RAT"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "6c43a753-9565-48b2-a372-4210bb1e0d75" ascii nocase wide
        $typelibguid1 = "92ba2a7e-c198-4d43-929e-1cfe54b64d95" ascii nocase wide
        $typelibguid2 = "4cb9bbee-fb92-44fa-a427-b7245befc2f3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Browser_ExternalC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/Browser-ExternalC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "10a730cd-9517-42d5-b3e3-a2383515cca9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_OffensivePowerShellTasking {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d432c332-3b48-4d06-bedb-462e264e6688" ascii nocase wide
        $typelibguid1 = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DoHC2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SpiderLabs/DoHC2"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "9877a948-2142-4094-98de-e0fbb1bc4062" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SyscallPOC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SolomonSklash/SyscallPOC"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "1e54637b-c887-42a9-af6a-b4bd4e28cda9" ascii nocase wide
        $typelibguid1 = "198d5599-d9fc-4a74-87f4-5077318232ad" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Pen_Test_Tools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/awillard1/Pen-Test-Tools"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii nocase wide
        $typelibguid1 = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii nocase wide
        $typelibguid2 = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii nocase wide
        $typelibguid3 = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii nocase wide
        $typelibguid4 = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii nocase wide
        $typelibguid5 = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii nocase wide
        $typelibguid6 = "a4043d4c-167b-4326-8be4-018089650382" ascii nocase wide
        $typelibguid7 = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii nocase wide
        $typelibguid8 = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii nocase wide
        $typelibguid9 = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii nocase wide
        $typelibguid10 = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii nocase wide
        $typelibguid11 = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_The_Collection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Tlgyt/The-Collection"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii nocase wide
        $typelibguid1 = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii nocase wide
        $typelibguid2 = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii nocase wide
        $typelibguid3 = "5f19919d-cd51-4e77-973f-875678360a6f" ascii nocase wide
        $typelibguid4 = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Change_Lockscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/Change-Lockscreen"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "78642ab3-eaa6-4e9c-a934-e7b0638bc1cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LOLBITS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Kudaes/LOLBITS"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "29d09aa4-ea0c-47c2-973c-1d768087d527" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Keylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BlackVikingPro/Keylogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "7afbc9bf-32d9-460f-8a30-35e30aa15879" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1337 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/neofito/CVE-2020-1337"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "d9c2e3c1-e9cc-42b0-a67c-b6e1a4f962cc" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpLogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "36e00152-e073-4da8-aa0c-375b6dd680c4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AsyncRAT_C_Sharp {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "619b7612-dfea-442a-a927-d997f99c497b" ascii nocase wide
        $typelibguid1 = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii nocase wide
        $typelibguid2 = "37e20baf-3577-4cd9-bb39-18675854e255" ascii nocase wide
        $typelibguid3 = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii nocase wide
        $typelibguid4 = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii nocase wide
        $typelibguid5 = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii nocase wide
        $typelibguid6 = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii nocase wide
        $typelibguid7 = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii nocase wide
        $typelibguid8 = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii nocase wide
        $typelibguid9 = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii nocase wide
        $typelibguid10 = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DarkFender {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xyg3n/DarkFender"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "12fdf7ce-4a7c-41b6-9b32-766ddd299beb" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

/* FPs with IronPython
rule HKTL_NET_GUID_IronKit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nshalabi/IronKit"
        author = "Arnim Rupp"
        score = 50
        date = "2020-12-13"
    strings:
        $typelibguid0 = "68e40495-c34a-4539-b43e-9e4e6f11a9fb" ascii nocase wide
        $typelibguid1 = "641cd52d-3886-4a74-b590-2a05621502a4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}
*/

rule HKTL_NET_GUID_MinerDropper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DylanAlloy/MinerDropper"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii nocase wide
        $typelibguid1 = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDomainSpray {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpDomainSpray"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "76ffa92b-429b-4865-970d-4e7678ac34ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_iSpyKeylogger {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/iSpyKeylogger"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "ccc0a386-c4ce-42ef-aaea-b2af7eff4ad8" ascii nocase wide
        $typelibguid1 = "816b8b90-2975-46d3-aac9-3c45b26437fa" ascii nocase wide
        $typelibguid2 = "279b5533-d3ac-438f-ba89-3fe9de2da263" ascii nocase wide
        $typelibguid3 = "88d3dc02-2853-4bf0-b6dc-ad31f5135d26" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SolarFlare {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mubix/solarflare"
        author = "Arnim Rupp"
        date = "2020-12-15"
    strings:
        $typelibguid0 = "ca60e49e-eee9-409b-8d1a-d19f1d27b7e4" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Snaffler {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/SnaffCon/Snaffler"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "2aa060b4-de88-4d2a-a26a-760c1cefec3e" ascii nocase wide
        $typelibguid1 = "b118802d-2e46-4e41-aac7-9ee890268f8b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShares {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpShares/"
        author = "Arnim Rupp"
        date = "2020-12-13"
    strings:
        $typelibguid0 = "fe9fdde5-3f38-4f14-8c64-c3328c215cf2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpEDRChecker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PwnDexter/SharpEDRChecker"
        author = "Arnim Rupp"
        date = "2020-12-18"
    strings:
        $typelibguid0 = "bdfee233-3fed-42e5-aa64-492eb2ac7047" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipHistory {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpClipHistory"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "1126d5b4-efc7-4b33-a594-b963f107fe82" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Absinthe {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cameronhotchkies/Absinthe"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "9936ae73-fb4e-4c5e-a5fb-f8aaeb3b9bd6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ExploitRemotingService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/ExploitRemotingService"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii nocase wide
        $typelibguid1 = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii nocase wide
        $typelibguid2 = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Xploit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shargon/Xploit"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii nocase wide
        $typelibguid1 = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii nocase wide
        $typelibguid2 = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii nocase wide
        $typelibguid3 = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii nocase wide
        $typelibguid4 = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii nocase wide
        $typelibguid5 = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii nocase wide
        $typelibguid6 = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii nocase wide
        $typelibguid7 = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii nocase wide
        $typelibguid8 = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii nocase wide
        $typelibguid9 = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii nocase wide
        $typelibguid10 = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoC {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/thezdi/PoC"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "89f9d411-e273-41bb-8711-209fd251ca88" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpGPOAbuse {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FSecureLABS/SharpGPOAbuse"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "4f495784-b443-4838-9fa6-9149293af785" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Watson {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/Watson"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "49ad5f38-9e37-4967-9e84-fe19c7434ed7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_StandIn {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/StandIn"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "01c142ba-7af1-48d6-b185-81147a2f7db7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_azure_password_harvesting {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/guardicore/azure_password_harvesting"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "7ad1ff2d-32ac-4c54-b615-9bb164160dac" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PowerOPS {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fdiskyou/PowerOPS"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "2a3c5921-7442-42c3-8cb9-24f21d0b2414" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Random_CSharpTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/xorrior/Random-CSharpTools"
        author = "Arnim Rupp"
        date = "2020-12-21"
    strings:
        $typelibguid0 = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii nocase wide
        $typelibguid1 = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii nocase wide
        $typelibguid2 = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii nocase wide
        $typelibguid3 = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii nocase wide
        $typelibguid4 = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii nocase wide
        $typelibguid5 = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii nocase wide
        $typelibguid6 = "60116613-c74e-41b9-b80e-35e02f25891e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_0668 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RedCursorSecurityConsulting/CVE-2020-0668"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "1b4c5ec1-2845-40fd-a173-62c450f12ea5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WindowsRpcClients {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/WindowsRpcClients"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "843d8862-42eb-49ee-94e6-bca798dd33ea" ascii nocase wide
        $typelibguid1 = "632e4c3b-3013-46fc-bc6e-22828bf629e3" ascii nocase wide
        $typelibguid2 = "a2091d2f-6f7e-4118-a203-4cea4bea6bfa" ascii nocase wide
        $typelibguid3 = "950ef8ce-ec92-4e02-b122-0d41d83065b8" ascii nocase wide
        $typelibguid4 = "d51301bc-31aa-4475-8944-882ecf80e10d" ascii nocase wide
        $typelibguid5 = "823ff111-4de2-4637-af01-4bdc3ca4cf15" ascii nocase wide
        $typelibguid6 = "5d28f15e-3bb8-4088-abe0-b517b31d4595" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpFruit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpFruit"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "3da2f6de-75be-4c9d-8070-08da45e79761" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWitness {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/SharpWitness"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b9f6ec34-4ccc-4247-bcef-c1daab9b4469" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RexCrypter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/syrex1013/RexCrypter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "10cd7c1c-e56d-4b1b-80dc-e4c496c5fec5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPersist {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/SharPersist"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9d1b853e-58f1-4ba5-aefc-5c221ca30e48" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1253 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/padovah4ck/CVE-2019-1253"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "584964c1-f983-498d-8370-23e27fdd0399" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_scout {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/scout"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d9c76e82-b848-47d4-8f22-99bf22a8ee11" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Grouper2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/l0ss/Grouper2/"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "5decaea3-2610-4065-99dc-65b9b4ba6ccd" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CasperStager {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ustayready/CasperStager"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "c653a9f2-0939-43c8-9b93-fed5e2e4c7e6" ascii nocase wide
        $typelibguid1 = "48dfc55e-6ae5-4a36-abef-14bc09d7510b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TellMeYourSecrets {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/TellMeYourSecrets"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9b448062-7219-4d82-9a0a-e784c4b3aa27" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExcel4_DCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpExcel4-DCOM"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "68b83ce5-bbd9-4ee3-b1cc-5e9223fab52b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpShooter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/SharpShooter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "56598f1c-6d88-4994-a392-af337abe5777" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NoMSBuild {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/NoMSBuild"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "034a7b9f-18df-45da-b870-0e1cef500215" ascii nocase wide
        $typelibguid1 = "59b449d7-c1e8-4f47-80b8-7375178961db" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TeleShadow2 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ParsingTeam/TeleShadow2"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "42c5c356-39cf-4c07-96df-ebb0ccf78ca4" ascii nocase wide
        $typelibguid1 = "0242b5b1-4d26-413e-8c8c-13b4ed30d510" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BadPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BeichenDream/BadPotato"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0527a14f-1591-4d94-943e-d6d784a50549" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LethalHTA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/codewhitesec/LethalHTA"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "784cde17-ff0f-4e43-911a-19119e89c43f" ascii nocase wide
        $typelibguid1 = "7e2de2c0-61dc-43ab-a0ec-c27ee2172ea6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStat {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Raikia/SharpStat"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ffc5c721-49c8-448d-8ff4-2e3a7b7cc383" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SneakyService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/SneakyService"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "897819d5-58e0-46a0-8e1a-91ea6a269d84" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/anthemtotheego/SharpExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "7fbad126-e21c-4c4e-a9f0-613fcf585a71" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCOM {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpCOM"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "51960f7d-76fe-499f-afbd-acabd7ba50d1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inception {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/two06/Inception"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sharpwmi {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/QAX-A-Team/sharpwmi"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "bb357d38-6dc1-4f20-a54c-d664bd20677e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2019_1064 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/RythmStick/CVE-2019-1064"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ff97e98a-635e-4ea9-b2d0-1a13f6bdbc38" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Tokenvator {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Tokenvator"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "4b2b3bd4-d28f-44cc-96b3-4a2f64213109" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_WheresMyImplant {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/WheresMyImplant"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cca59e4e-ce4d-40fc-965f-34560330c7e6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Naga {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/byt3bl33d3r/Naga"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "99428732-4979-47b6-a323-0bb7d6d07c95" ascii nocase wide
        $typelibguid1 = "a2c9488f-6067-4b17-8c6f-2d464e65c535" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpBox {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/P1CKLES/SharpBox"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "616c1afb-2944-42ed-9951-bf435cadb600" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_rundotnetdll32 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/rundotnetdll32"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "a766db28-94b6-4ed1-aef9-5200bbdd8ca7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AntiDebug {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/AntiDebug"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "997265c1-1342-4d44-aded-67964a32f859" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvisibleRegistry {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/DInvisibleRegistry"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "31d576fb-9fb9-455e-ab02-c78981634c65" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_TikiTorch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/TikiTorch"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "806c6c72-4adc-43d9-b028-6872fa48d334" ascii nocase wide
        $typelibguid1 = "2ef9d8f7-6b77-4b75-822b-6a53a922c30f" ascii nocase wide
        $typelibguid2 = "8f5f3a95-f05c-4dce-8bc3-d0a0d4153db6" ascii nocase wide
        $typelibguid3 = "1f707405-9708-4a34-a809-2c62b84d4f0a" ascii nocase wide
        $typelibguid4 = "97421325-b6d8-49e5-adf0-e2126abc17ee" ascii nocase wide
        $typelibguid5 = "06c247da-e2e1-47f3-bc3c-da0838a6df1f" ascii nocase wide
        $typelibguid6 = "fc700ac6-5182-421f-8853-0ad18cdbeb39" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_HiveJack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Viralmaniar/HiveJack"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e12e62fe-bea3-4989-bf04-6f76028623e3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DecryptAutoLogon {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/securesean/DecryptAutoLogon"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "015a37fc-53d0-499b-bffe-ab88c5086040" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnstoppableService {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/UnstoppableService"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWMI {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/SharpWMI"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6dd22880-dac5-4b4d-9c91-8c35cc7b8180" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EWSToolkit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/EWSToolkit"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "ca536d67-53c9-43b5-8bc8-9a05fdc567ed" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SweetPotato {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/CCob/SweetPotato"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6aeb5004-6093-4c23-aeae-911d64cacc58" ascii nocase wide
        $typelibguid1 = "1bf9c10f-6f89-4520-9d2e-aaf17d17ba5e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_memscan {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nccgroup/memscan"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "79462f87-8418-4834-9356-8c11e44ce189" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpStay {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpStay"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2963c954-7b1e-47f5-b4fa-2fc1f0d56aea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpLocker {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Pickfordmatt/SharpLocker"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "a6f8500f-68bc-4efc-962a-6c6e68d893af" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SauronEye {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/vivami/SauronEye"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0f43043d-8957-4ade-a0f4-25c1122e8118" ascii nocase wide
        $typelibguid1 = "086bf0ca-f1e4-4e8f-9040-a8c37a49fa26" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_sitrep {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/sitrep"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "12963497-988f-46c0-9212-28b4b2b1831b" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpClipboard {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpClipboard"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "97484211-4726-4129-86aa-ae01d17690be" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCookieMonster {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/m0rv4i/SharpCookieMonster"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "566c5556-1204-4db9-9dc8-a24091baaa8e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_p0wnedShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Cn33liz/p0wnedShell"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2e9b1462-f47c-48ca-9d85-004493892381" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMove {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpMove"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "8bf82bbe-909c-4777-a2fc-ea7c070ff43e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_C_Sharp_R_A_T_Client {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpPrinter {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rvrsh3ll/SharpPrinter"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "41b2d1e5-4c5d-444c-aa47-629955401ed9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EvilFOCA {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/ElevenPaths/EvilFOCA"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "f26bdb4a-5846-4bec-8f52-3c39d32df495" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshC2_Misc {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/PoshC2_Misc"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "85773eb7-b159-45fe-96cd-11bad51da6de" ascii nocase wide
        $typelibguid1 = "9d32ad59-4093-420d-b45c-5fff391e990d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharpire {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xbadjuju/Sharpire"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "39b75120-07fe-4833-a02e-579ff8b68331" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_SMBExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-SMBExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "344ee55a-4e32-46f2-a003-69ad52b55945" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MiscTools {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/rasta-mouse/MiscTools"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "384e9647-28a9-4835-8fa7-2472b1acedc0" ascii nocase wide
        $typelibguid1 = "d7ec0ef5-157c-4533-bbcd-0fe070fbf8d9" ascii nocase wide
        $typelibguid2 = "10085d98-48b9-42a8-b15b-cb27a243761b" ascii nocase wide
        $typelibguid3 = "6aacd159-f4e7-4632-bad1-2ae8526a9633" ascii nocase wide
        $typelibguid4 = "49a6719e-11a8-46e6-ad7a-1db1be9fea37" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemoryMapper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jasondrawdy/MemoryMapper"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b9fbf3ac-05d8-4cd5-9694-b224d4e6c0ea" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_VanillaRAT {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/DannyTheSloth/VanillaRAT"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii nocase wide
        $typelibguid1 = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_UnmanagedPowerShell {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/leechristensen/UnmanagedPowerShell"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "dfc4eebb-7384-4db5-9bad-257203029bd9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Quasar {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/quasar/Quasar"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cfda6d2e-8ab3-4349-b89a-33e1f0dab32b" ascii nocase wide
        $typelibguid1 = "c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAdidnsdump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/b4rtik/SharpAdidnsdump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "cdb02bc2-5f62-4c8a-af69-acc3ab82e741" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/tyranid/DotNetToJScript"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "7e3f231c-0d0b-4025-812c-0ef099404861" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Inferno {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/LimerBoy/Inferno"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "26d498f7-37ae-476c-97b0-3761e3a919f0" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSearch {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/djhohnstein/SharpSearch"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "98fee742-8410-4f20-8b2d-d7d789ab003d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSecDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/G0ldenGunSec/SharpSecDump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e2fdd6cc-9886-456c-9021-ee2c47cf67b7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Net_GPPPassword {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/Net-GPPPassword"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "00fcf72c-d148-4dd0-9ca4-0181c4bd55c3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_FileSearcher {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/NVISO-BE/FileSearcher"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2c879479-5027-4ce9-aaac-084db0e6d630" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADFSDump {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/fireeye/ADFSDump"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "9ee27d63-6ac9-4037-860b-44e91bae7f0d" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpRDP {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/0xthirteen/SharpRDP"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "f1df1d0f-ff86-4106-97a8-f95aaf525c54" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCall {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jhalon/SharpCall"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "c1b0a923-0f17-4bc8-ba0f-c87aff43e799" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ysoserial_net {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/pwntester/ysoserial.net"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e1e8c029-f7cd-4bd1-952e-e819b41520f0" ascii nocase wide
        $typelibguid1 = "6b40fde7-14ea-4f57-8b7b-cc2eb4a25e6c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ManagedInjection {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malcomvetter/ManagedInjection"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii nocase wide
        $typelibguid1 = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii nocase wide
        $typelibguid2 = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSocks {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/nettitude/SharpSocks"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "2f43992e-5703-4420-ad0b-17cb7d89c956" ascii nocase wide
        $typelibguid1 = "86d10a34-c374-4de4-8e12-490e5e65ddff" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Sharp_WMIExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/checkymander/Sharp-WMIExec"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "0a63b0a1-7d1a-4b84-81c3-bbbfe9913029" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_KeeThief {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/KeeThief"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid1 = "39aa6f93-a1c9-497f-bad2-cc42a61d5710" ascii nocase wide
        $typelibguid3 = "3fca8012-3bad-41e4-91f4-534aa9a44f96" ascii nocase wide
        $typelibguid4 = "ea92f1e6-3f34-48f8-8b0a-f2bbc19220ef" ascii nocase wide
        $typelibguid5 = "c23b51c4-2475-4fc6-9b3a-27d0a2b99b0f" ascii nocase wide
        $typelibguid6 = "94432a8e-3e06-4776-b9b2-3684a62bb96a" ascii nocase wide
        $typelibguid7 = "80ba63a4-7d41-40e9-a722-6dd58b28bf7e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_fakelogonscreen {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/bitsadmin/fakelogonscreen"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "d35a55bd-3189-498b-b72f-dc798172e505" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PoshSecFramework {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/PoshSec/PoshSecFramework"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "b1ac6aa0-2f1a-4696-bf4b-0e41cf2f4b6b" ascii nocase wide
        $typelibguid1 = "78bfcfc2-ef1c-4514-bce6-934b251666d2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAttack {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jaredhaight/SharpAttack"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Altman {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/keepwn/Altman"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "64cdcd2b-7356-4079-af78-e22210e66154" ascii nocase wide
        $typelibguid1 = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii nocase wide
        $typelibguid2 = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii nocase wide
        $typelibguid3 = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii nocase wide
        $typelibguid4 = "9514574d-6819-44f2-affa-6158ac1143b3" ascii nocase wide
        $typelibguid5 = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii nocase wide
        $typelibguid6 = "9624b72e-9702-4d78-995b-164254328151" ascii nocase wide
        $typelibguid7 = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii nocase wide
        $typelibguid8 = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii nocase wide
        $typelibguid9 = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii nocase wide
        $typelibguid10 = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii nocase wide
        $typelibguid11 = "231987a1-ea32-4087-8963-2322338f16f6" ascii nocase wide
        $typelibguid12 = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii nocase wide
        $typelibguid13 = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii nocase wide
        $typelibguid14 = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii nocase wide
        $typelibguid15 = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii nocase wide
        $typelibguid16 = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii nocase wide
        $typelibguid17 = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BrowserPass {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/jabiel/BrowserPass"
        author = "Arnim Rupp"
        date = "2020-12-28"
    strings:
        $typelibguid0 = "3cb59871-0dce-453b-857a-2d1e515b0b66" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Mythic {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/its-a-feature/Mythic"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "91f7a9da-f045-4239-a1e9-487ffdd65986" ascii nocase wide
        $typelibguid1 = "0405205c-c2a0-4f9a-a221-48b5c70df3b6" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Nuages {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/p3nt4/Nuages"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "e9e80ac7-4c13-45bd-9bde-ca89aadf1294" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSniper {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/HunnicCyber/SharpSniper"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "c8bb840c-04ce-4b60-a734-faf15abf7b18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHound3 {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/BloodHoundAD/SharpHound3"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "a517a8de-5834-411d-abda-2d0e1766539c" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlockEtw {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/Soledge/BlockEtw"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "daedf7b3-8262-4892-adc4-425dd5f85bca" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpWifiGrabber {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/r3nhat/SharpWifiGrabber"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "c0997698-2b73-4982-b25b-d0578d1323c2" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpMapExec {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/cube0x0/SharpMapExec"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "bd5220f7-e1fb-41d2-91ec-e4c50c6e9b9f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_k8fly {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/zzwlpx/k8fly"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "13b6c843-f3d4-4585-b4f3-e2672a47931e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Stealer {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/malwares/Stealer"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "8fcd4931-91a2-4e18-849b-70de34ab75df" ascii nocase wide
        $typelibguid1 = "e48811ca-8af8-4e73-85dd-2045b9cca73a" ascii nocase wide
        $typelibguid2 = "d3d8a1cc-e123-4905-b3de-374749122fcf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PortTran {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/k8gege/PortTran"
        author = "Arnim Rupp"
        date = "2020-12-29"
    strings:
        $typelibguid0 = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii nocase wide
        $typelibguid1 = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


rule HKTL_NET_GUID_gray_keylogger_2 {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/graysuit/gray-keylogger-2"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "e94ca3ff-c0e5-4d1a-ad5e-f6ebbe365067" ascii nocase wide
        $typelibguid1 = "1ed07564-b411-4626-88e5-e1cd8ecd860a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_Miner {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_BlackNET {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/BlackHacker511/BlackNET"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "c2b90883-abee-4cfa-af66-dfd93ec617a5" ascii nocase wide
        $typelibguid1 = "8bb6f5b4-e7c7-4554-afd1-48f368774837" ascii nocase wide
        $typelibguid2 = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii nocase wide
        $typelibguid3 = "9ac18cdc-3711-4719-9cfb-5b5f2d51fd5a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_PlasmaRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/PlasmaRAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "b8a2147c-074c-46e1-bb99-c8431a6546ce" ascii nocase wide
        $typelibguid1 = "0fcfde33-213f-4fb6-ac15-efb20393d4f3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Lime_RAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/NYAN-x-CAT/Lime-RAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "e58ac447-ab07-402a-9c96-95e284a76a8d" ascii nocase wide
        $typelibguid1 = "8fb35dab-73cd-4163-8868-c4dbcbdf0c17" ascii nocase wide
        $typelibguid2 = "37845f5b-35fe-4dce-bbec-2d07c7904fb0" ascii nocase wide
        $typelibguid3 = "83c453cf-0d29-4690-b9dc-567f20e63894" ascii nocase wide
        $typelibguid4 = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" ascii nocase wide
        $typelibguid5 = "eaaeccf6-75d2-4616-b045-36eea09c8b28" ascii nocase wide
        $typelibguid6 = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" ascii nocase wide
        $typelibguid7 = "e2cc7158-aee6-4463-95bf-fb5295e9e37a" ascii nocase wide
        $typelibguid8 = "d04ecf62-6da9-4308-804a-e789baa5cc38" ascii nocase wide
        $typelibguid9 = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" ascii nocase wide
        $typelibguid10 = "212cdfac-51f1-4045-a5c0-6e638f89fce0" ascii nocase wide
        $typelibguid11 = "c1b608bb-7aed-488d-aa3b-0c96625d26c0" ascii nocase wide
        $typelibguid12 = "4c84e7ec-f197-4321-8862-d5d18783e2fe" ascii nocase wide
        $typelibguid13 = "3fc17adb-67d4-4a8d-8770-ecfd815f73ee" ascii nocase wide
        $typelibguid14 = "f1ab854b-6282-4bdf-8b8b-f2911a008948" ascii nocase wide
        $typelibguid15 = "aef6547e-3822-4f96-9708-bcf008129b2b" ascii nocase wide
        $typelibguid16 = "a336f517-bca9-465f-8ff8-2756cfd0cad9" ascii nocase wide
        $typelibguid17 = "5de018bd-941d-4a5d-bed5-fbdd111aba76" ascii nocase wide
        $typelibguid18 = "bbfac1f9-cd4f-4c44-af94-1130168494d0" ascii nocase wide
        $typelibguid19 = "1c79cea1-ebf3-494c-90a8-51691df41b86" ascii nocase wide
        $typelibguid20 = "927104e1-aa17-4167-817c-7673fe26d46e" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_njRAT {
    meta:
        description = "Detects VB.NET red/black-team tools via typelibguid"
        reference = "https://github.com/mwsrc/njRAT"
        author = "Arnim Rupp"
        date = "2020-12-30"
    strings:
        $typelibguid0 = "5a542c1b-2d36-4c31-b039-26a88d3967da" ascii nocase wide
        $typelibguid1 = "6b07082a-9256-42c3-999a-665e9de49f33" ascii nocase wide
        $typelibguid2 = "c0a9a70f-63e8-42ca-965d-73a1bc903e62" ascii nocase wide
        $typelibguid3 = "70bd11de-7da1-4a89-b459-8daacc930c20" ascii nocase wide
        $typelibguid4 = "fc790ee5-163a-40f9-a1e2-9863c290ff8b" ascii nocase wide
        $typelibguid5 = "cb3c28b2-2a4f-4114-941c-ce929fec94d3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Manager {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/Manager"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "dda73ee9-0f41-4c09-9cad-8215abd60b33" ascii nocase wide
        $typelibguid1 = "6a0f2422-d4d1-4b7e-84ad-56dc0fd2dfc5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_neo_ConfuserEx {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/XenocodeRCE/neo-ConfuserEx"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "e98490bb-63e5-492d-b14e-304de928f81a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpAllowedToAct {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/pkb1s/SharpAllowedToAct"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "dac5448a-4ad1-490a-846a-18e4e3e0cf9a" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SuperSQLInjectionV1 {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shack2/SuperSQLInjectionV1"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "d5688068-fc89-467d-913f-037a785caca7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_ADSearch {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/tomcarver16/ADSearch"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "4da5f1b7-8936-4413-91f7-57d6e072b4a7" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_privilege_escalation_awesome_scripts_suite {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "1928358e-a64b-493f-a741-ae8e3d029374" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CVE_2020_1206_POC {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii nocase wide
        $typelibguid1 = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii nocase wide
        $typelibguid2 = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DInvoke {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/DInvoke"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "b77fdab5-207c-4cdb-b1aa-348505c54229" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpChisel {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/shantanu561993/SharpChisel"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "f5f21e2d-eb7e-4146-a7e1-371fd08d6762" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpScribbles {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/V1V1/SharpScribbles"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "aa61a166-31ef-429d-a971-ca654cd18c3b" ascii nocase wide
        $typelibguid1 = "0dc1b824-c6e7-4881-8788-35aecb34d227" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpReg {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpReg"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_MemeVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TobitoFatitoRE/MemeVM"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii nocase wide
        $typelibguid1 = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii nocase wide
        $typelibguid2 = "14d5d12e-9a32-4516-904e-df3393626317" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpDir {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpDir"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "c7a07532-12a3-4f6a-a342-161bb060b789" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_AtYourService {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/AtYourService"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "bc72386f-8b4c-44de-99b7-b06a8de3ce3f" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_LockLess {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/GhostPack/LockLess"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "a91421cb-7909-4383-ba43-c2992bbbac22" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_EasyNet {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/EasyNet"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "3097d856-25c2-42c9-8d59-2cdad8e8ea12" ascii nocase wide
        $typelibguid1 = "ba33f716-91e0-4cf7-b9bd-b4d558f9a173" ascii nocase wide
        $typelibguid2 = "37d6dd3f-5457-4d8b-a2e1-c7b156b176e5" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpByeBear {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/S3cur3Th1sSh1t/SharpByeBear"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "a6b84e35-2112-4df2-a31b-50fde4458c5e" ascii nocase wide
        $typelibguid1 = "3e82f538-6336-4fff-aeec-e774676205da" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHide {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/outflanknl/SharpHide"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "443d8cbf-899c-4c22-b4f6-b7ac202d4e37" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpSvc {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jnqpblc/SharpSvc"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "52856b03-5acd-45e0-828e-13ccb16942d1" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpCrashEventLog {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/slyd0g/SharpCrashEventLog"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "98cb495f-4d47-4722-b08f-cefab2282b18" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_DotNetToJScript_LanguageModeBreakout {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/DotNetToJScript-LanguageModeBreakout"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "deadb33f-fa94-41b5-813d-e72d8677a0cf" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharPermission {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mitchmoser/SharPermission"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "84d2b661-3267-49c8-9f51-8f72f21aea47" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_RegistryStrikesBack {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "90ebd469-d780-4431-9bd8-014b00057665" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_CloneVault {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/mdsecactivebreach/CloneVault"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "0a344f52-6780-4d10-9a4a-cb9439f9d3de" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_donut {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/TheWover/donut"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "98ca74c7-a074-434d-9772-75896e73ceaa" ascii nocase wide
        $typelibguid1 = "3c9a6b88-bed2-4ba8-964c-77ec29bf1846" ascii nocase wide
        $typelibguid2 = "4fcdf3a3-aeef-43ea-9297-0d3bde3bdad2" ascii nocase wide
        $typelibguid3 = "361c69f5-7885-4931-949a-b91eeab170e3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_SharpHandler {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/jfmaes/SharpHandler"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "46e39aed-0cff-47c6-8a63-6826f147d7bd" ascii nocase wide
        $typelibguid1 = "11dc83c6-8186-4887-b228-9dc4fd281a23" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_Driver_Template {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/FuzzySecurity/Driver-Template"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "bdb79ad6-639f-4dc2-8b8a-cd9107da3d69" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}

rule HKTL_NET_GUID_NashaVM {
    meta:
        description = "Detects .NET red/black-team tools via typelibguid"
        reference = "https://github.com/Mrakovic-ORG/NashaVM"
        author = "Arnim Rupp"
        date = "2021-01-21"
    strings:
        $typelibguid0 = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii nocase wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}


/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/* Rule Set ----------------------------------------------------------------- */

rule Empire_Invoke_MetasploitPayload {
   meta:
      description = "Detects Empire component - file Invoke-MetasploitPayload.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a85ca27537ebeb79601b885b35ddff6431860b5852c6a664d32a321782808c54"
   strings:
      $s1 = "$ProcessInfo.Arguments=\"-nop -c $DownloadCradle\"" fullword ascii
      $s2 = "$PowershellExe=$env:windir+'\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe'" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 9KB and 1 of them ) or all of them
}

rule Empire_Exploit_Jenkins {
   meta:
      description = "Detects Empire component - file Exploit-Jenkins.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a5182cccd82bb9984b804b365e07baba78344108f225b94bd12a59081f680729"
   strings:
      $s1 = "$postdata=\"script=println+new+ProcessBuilder%28%27\"+$($Cmd)+\"" ascii
      $s2 = "$url = \"http://\"+$($Rhost)+\":\"+$($Port)+\"/script\"" fullword ascii
      $s3 = "$Cmd = [System.Web.HttpUtility]::UrlEncode($Cmd)" fullword ascii
   condition:
      ( uint16(0) == 0x6620 and filesize < 7KB and 1 of them ) or all of them
}

rule Empire_Get_SecurityPackages {
   meta:
      description = "Detects Empire component - file Get-SecurityPackages.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
   strings:
      $s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
      $s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}

rule Empire_Invoke_PowerDump {
   meta:
      description = "Detects Empire component - file Invoke-PowerDump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"
   strings:
      $x16 = "$enc = Get-PostHashdumpScript" fullword ascii
      $x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
      $x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii
   condition:
      ( uint16(0) == 0x2023 and filesize < 60KB and 1 of them ) or all of them
}

rule Empire_Install_SSP {
   meta:
      description = "Detects Empire component - file Install-SSP.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7fd921a23950334257dda57b99e03c1e1594d736aab2dbfe9583f99cd9b1d165"
   strings:
      $s1 = "Install-SSP -Path .\\mimilib.dll" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 20KB and 1 of them ) or all of them
}

rule Empire_Invoke_ShellcodeMSIL {
   meta:
      description = "Detects Empire component - file Invoke-ShellcodeMSIL.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a9c6c9eb67bde4a8ce2c0858e353e19627b17ee2a7215fa04a19010d3ef153f"
   strings:
      $s1 = "$FinalShellcode.Length" fullword ascii
      $s2 = "@(0x60,0xE8,0x04,0,0,0,0x61,0x31,0xC0,0xC3)" fullword ascii
      $s3 = "@(0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57," fullword ascii
      $s4 = "$TargetMethod.Invoke($null, @(0x11112222)) | Out-Null" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire__Users_neo_code_Workspace_Empire_4sigs_PowerUp {
   meta:
      description = "Detects Empire component - file PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
   strings:
      $x2 = "$PoolPasswordCmd = 'c:\\windows\\system32\\inetsrv\\appcmd.exe list apppool" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - file Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
      $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Get_GPPPassword {
   meta:
      description = "Detects Empire component - file Get-GPPPassword.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "55a4519c4f243148a971e4860225532a7ce730b3045bde3928303983ebcc38b0"
   strings:
      $s1 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
      $s2 = "$XMlFiles += Get-ChildItem -Path \"\\\\$DomainController\\SYSVOL\" -Recurse" ascii
      $s3 = "function Get-DecryptedCpassword {" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_SmbScanner {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Exploit_JBoss {
   meta:
      description = "Detects Empire component - file Exploit-JBoss.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9ea3e00b299e644551d90bbee0ce3e4e82445aa15dab7adb7fcc0b7f1fe4e653"
   strings:
      $s1 = "Exploit-JBoss" fullword ascii
      $s2 = "$URL = \"http$($SSL)://\" + $($Rhost) + ':' + $($Port)" ascii
      $s3 = "\"/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service" ascii
      $s4 = "http://blog.rvrsh3ll.net" fullword ascii
      $s5 = "Remote URL to your own WARFile to deploy." fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_dumpCredStore {
   meta:
      description = "Detects Empire component - file dumpCredStore.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"
   strings:
      $x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
      $s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
      $s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 40KB and 1 of them ) or all of them
}

rule Empire_Invoke_EgressCheck {
   meta:
      description = "Detects Empire component - file Invoke-EgressCheck.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
   strings:
      $s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_ReflectivePick_x64_orig {
   meta:
      description = "Detects Empire component - file ReflectivePick_x64_orig.dll"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "a8c1b108a67e7fc09f81bd160c3bafb526caf3dbbaf008efb9a96f4151756ff2"
   strings:
      $s1 = "\\PowerShellRunner.pdb" fullword ascii
      $s2 = "PowerShellRunner.dll" fullword wide
      $s3 = "ReflectivePick_x64.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them ) or all of them
}

rule Empire_Out_Minidump {
   meta:
      description = "Detects Empire component - file Out-Minidump.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"
   strings:
      $s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
      $s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}

rule Empire_Invoke_PsExec {
   meta:
      description = "Detects Empire component - file Invoke-PsExec.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
   strings:
      $s1 = "Invoke-PsExecCmd" fullword ascii
      $s2 = "\"[*] Executing service .EXE" fullword ascii
      $s3 = "$cmd = \"%COMSPEC% /C echo $Command ^> %systemroot%\\Temp\\" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 50KB and 1 of them ) or all of them
}

rule Empire_Invoke_PostExfil {
   meta:
      description = "Detects Empire component - file Invoke-PostExfil.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "00c0479f83c3dbbeff42f4ab9b71ca5fe8cd5061cb37b7b6861c73c54fd96d3e"
   strings:
      $s1 = "# upload to a specified exfil URI" fullword ascii
      $s2 = "Server path to exfil to." fullword ascii
   condition:
      ( uint16(0) == 0x490a and filesize < 2KB and 1 of them ) or all of them
}

rule Empire_Invoke_SMBAutoBrute {
   meta:
      description = "Detects Empire component - file Invoke-SMBAutoBrute.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7950f8abdd8ee09ed168137ef5380047d9d767a7172316070acc33b662f812b2"
   strings:
      $s1 = "[*] PDC: LAB-2008-DC1.lab.com" fullword ascii
      $s2 = "$attempts = Get-UserBadPwdCount $userid $dcs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Get_Keystrokes {
   meta:
      description = "Detects Empire component - file Get-Keystrokes.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "c36e71db39f6852f78df1fa3f67e8c8a188bf951e96500911e9907ee895bf8ad"
   strings:
      $s1 = "$RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 30KB and 1 of them ) or all of them
}

rule Empire_Invoke_DllInjection {
   meta:
      description = "Detects Empire component - file Invoke-DllInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
   strings:
      $s1 = "-Dll evil.dll" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 40KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig {
   meta:
      description = "Detects Empire component - file KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
   strings:
      $s1 = "$UserMasterKeyFiles = @(, $(Get-ChildItem -Path $UserMasterKeyFolder -Force | Select-Object -ExpandProperty FullName) )" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_SSHCommand {
   meta:
      description = "Detects Empire component - file Invoke-SSHCommand.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "cbaf086b14d5bb6a756cbda42943d4d7ef97f8277164ce1f7dd0a1843e9aa242"
   strings:
      $s1 = "$Base64 = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA" ascii
      $s2 = "Invoke-SSHCommand -ip 192.168.1.100 -Username root -Password test -Command \"id\"" fullword ascii
      $s3 = "Write-Verbose \"[*] Error loading dll\"" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 2000KB and 1 of them ) or all of them
}

/* Super Rules ------------------------------------------------------------- */

rule Empire_PowerShell_Framework_Gen1 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash3 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash4 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash5 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "Write-BytesToMemory -Bytes $Shellcode" ascii
      $s2 = "$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_PowerUp_Gen {
   meta:
      description = "Detects Empire component - from files PowerUp.ps1, PowerUp.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "ad9a5dff257828ba5f15331d59dd4def3989537b3b6375495d0c08394460268c"
   strings:
      $s1 = "$Result = sc.exe config $($TargetService.Name) binPath= $OriginalPath" fullword ascii
      $s2 = "$Result = sc.exe pause $($TargetService.Name)" fullword ascii
   condition:
      ( uint16(0) == 0x233c and filesize < 2000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen2 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-DCSync.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash6 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash8 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $x1 = "$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)" fullword ascii
      $s20 = "#Shellcode: CallDllMain.asm" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Agent_Gen {
   meta:
      description = "Detects Empire component - from files agent.ps1, agent.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
      hash2 = "380fd09bfbe47d5c8c870c1c97ff6f44982b699b55b61e7c803d3423eb4768db"
   strings:
      $s1 = "$wc.Headers.Add(\"User-Agent\",$script:UserAgent)" fullword ascii
      $s2 = "$min = [int]((1-$script:AgentJitter)*$script:AgentDelay)" fullword ascii
      $s3 = "if ($script:AgentDelay -ne 0){" fullword ascii
   condition:
      ( uint16(0) == 0x660a and filesize < 100KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen3 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash3 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash4 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "if (($PEInfo.FileType -ieq \"DLL\") -and ($RemoteProcHandle -eq [IntPtr]::Zero))" fullword ascii
      $s2 = "remote DLL injection" ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_InveighRelay_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-InveighRelay.ps1, Invoke-InveighRelay.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "21b90762150f804485219ad36fa509aeda210d46453307a9761c816040312f41"
   strings:
      $s1 = "$inveigh.SMBRelay_failed_list.Add(\"$HTTP_NTLM_domain_string\\$HTTP_NTLM_user_string $SMBRelayTarget\")" fullword ascii
      $s2 = "$NTLM_challenge_base64 = [System.Convert]::ToBase64String($HTTP_NTLM_bytes)" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 200KB and 1 of them ) or all of them
}

rule Empire_KeePassConfig_Gen {
   meta:
      description = "Detects Empire component - from files KeePassConfig.ps1, KeePassConfig.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "5a76e642357792bb4270114d7cd76ce45ba24b0d741f5c6b916aeebd45cff2b3"
   strings:
      $s1 = "$KeePassXML = [xml](Get-Content -Path $KeePassXMLPath)" fullword ascii
   condition:
      ( uint16(0) == 0x7223 and filesize < 80KB and 1 of them ) or all of them
}

rule Empire_Invoke_Portscan_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-Portscan.ps1, Invoke-Portscan.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash2 = "cf7030be01fab47e79e4afc9e0d4857479b06a5f68654717f3bc1bc67a0f38d3"
   strings:
      $s1 = "Test-Port -h $h -p $Port -timeout $Timeout" fullword ascii
      $s2 = "1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 100KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen4 {
   meta:
      description = "Detects Empire component - from files Invoke-BypassUAC.ps1, Invoke-CredentialInjection.ps1, Invoke-CredentialInjection.ps1, Invoke-DCSync.ps1, Invoke-DllInjection.ps1, Invoke-Mimikatz.ps1, Invoke-PsExec.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1, Invoke-Shellcode.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "743c51334f17751cfd881be84b56f648edbdaf31f8186de88d094892edc644a9"
      hash2 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash3 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash4 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash5 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
      hash6 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
      hash7 = "0218be4323959fc6379489a6a5e030bb9f1de672326e5e5b8844ab5cedfdcf88"
      hash8 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash9 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
      hash10 = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
   strings:
      $s1 = "Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\\\')[-1].Equals('System.dll') }" fullword ascii
      $s2 = "# Get a handle to the module specified" fullword ascii
      $s3 = "$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))" fullword ascii
      $s4 = "$DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_CredentialInjection_Invoke_Mimikatz_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-Mimikatz.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "4725a57a5f8b717ce316f104e9472e003964f8eae41a67fd8c16b4228e3d00b3"
   strings:
      $s1 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle" fullword ascii
      $s2 = "$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 4000KB and 1 of them ) or all of them
}

rule Empire_Invoke_Gen {
   meta:
      description = "Detects Empire component - from files Invoke-DCSync.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "a3428a7d4f9e677623fadff61b2a37d93461123535755ab0f296aa3b0396eb28"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "$Shellcode1 += 0x48" fullword ascii
      $s2 = "$PEHandle = [IntPtr]::Zero" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 3000KB and 1 of them ) or all of them
}

rule Empire_PowerShell_Framework_Gen5 {
   meta:
      description = "Detects Empire component - from files Invoke-CredentialInjection.ps1, Invoke-PSInject.ps1, Invoke-ReflectivePEInjection.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      super_rule = 1
      hash1 = "1be3e3ec0e364db0c00fad2c59c7041e23af4dd59c4cc7dc9dcf46ca507cd6c8"
      hash2 = "61e5ca9c1e8759a78e2c2764169b425b673b500facaca43a26c69ff7e09f62c4"
      hash3 = "eaff29dd0da4ac258d85ecf8b042d73edb01b4db48c68bded2a8b8418dc688b5"
   strings:
      $s1 = "if ($ExeArgs -ne $null -and $ExeArgs -ne '')" fullword ascii
      $s2 = "$ExeArgs = \"ReflectiveExe $ExeArgs\"" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 1000KB and 1 of them ) or all of them
}

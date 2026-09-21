rule Linux_TheGentlemen_Affiliate_Variant {
    meta:
        author = "CyberCold"
        description = "Detects masqueraded containerd/dockerd binary deployed by an affiliate of The Gentlemen"
        incident_id = "INC-2026-09-16-01"
        date = "2026-09-21"
        mitre_attack = "T1036, T1027, T1497, T1071.004"
        confidence = "High"

    strings:
        // CGO Network Bridge & Custom WebSocket Proxy Hooks
        $cgo_net1 = "sym.net._C2func_getaddrinfo" ascii
        $cgo_net2 = "sym.net._C2func_getnameinfo" ascii
        $ws_proxy1 = "sym.github.com_gorilla_websocket._proxy_socks5_.Dial" ascii
        $ws_proxy2 = "sym.github.com_gorilla_websocket._proxy_socks5_.connect" ascii
        
        // Tor Fallback / SOCKS5 Proxy Transport Identifier
        $onion_fallback = "listen.onion" ascii

        // gRPC Health Checking & Binary Logging Capabilities
        $grpc_log1 = "grpc/binlog/v1/binarylog.proto" ascii
        $grpc_log2 = ".grpc.binarylog.v1.ClientHeader" ascii
        $grpc_log3 = ".grpc.binarylog.v1.ServerHeader" ascii
        $grpc_health = "grpc/health/v1/health.proto" ascii

        // Systemd Persistence over D-Bus
        $dbus = "obj.github.com_godbus_dbus..stmp_" ascii

        // HTML Character Entity Obfuscation Table Components
        $html_obf1 = "_boxDL_" ascii
        $html_obf2 = "_boxDR_" ascii
        $html_obf3 = "_Aacute_" ascii

        // Low-level hardware evasion instruction string
        $evasion = "Hyphenrdtscppopcntcmd_gounpigz" ascii

    condition:
        uint16(0) == 0x457F and // Must be an ELF binary
        (4 of ($cgo_net*, $ws_proxy*, $grpc_log*, $grpc_health, $dbus) or $onion_fallback) and 
        1 of ($html_obf*, $evasion)
}



rule CommieLoader : malware {
    meta:
        name        = "CommieLoader1"
        category    = "Malware"
        description = "Detects sideloaded DLL from CommieLoader."
        author      = "SRLabs"
        created     = "2026-06-19"
        reliability = 100
		score		= 100
        tlp         = "TLP:green"

    strings:
        $a1 = { 42656E75747A65726E616D65206B6F6E6E7465206E696368742067656C6573656E2077657264656E210A }
        $a2 = { 5F5F52554E54494D455F50534555444F5F52454C4F435F4C4953545F454E445F5F }
        $a3 = { 4B6F70696572746520455845202725732720616C7320766572737465636B74206D61726B696572742E0A }
        $a4 = { 5F557064617465725F56657273696F6E5F }


    condition:
        all of them
}
rule CommieLoader2 : malware {
    meta:
        name        = "CommieLoader2"
        category    = "Malware"
        description = "Persistence."
        author      = "SRLabs"
        created     = "2026-06-24"
        reliability = 100
		score		= 100
        tlp         = "TLP:green"

    strings:
        $a1 = { 536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E }
        $a2 = { 5F557064617465725F56657273696F6E5F }

    condition:
        all of them
}

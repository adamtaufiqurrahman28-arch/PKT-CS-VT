from __future__ import annotations


def hash_query(days: int, limit: int = 100) -> str:
    """Query 1: Ambil hash detection dari NGSIEM dan simpan sebagai crowdstrike_sha.csv."""
    return f"""
ExternalApiType=Event_EppDetectionSummaryEvent Tactic!=/Custom Intel/i
| ReadableTime := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="Asia/Jakarta")
| timeDelta := now() - @timestamp
| timeDeltaDays := timeDelta/1000/60/60/24
| round(timeDeltaDays)
| timeDeltaDays < {int(days)}
| SHA256String=*
| match(file="aid_master_main.csv", field=[AgentId], column=aid, include=[Version,ProductType], strict=false)
| $falcon/helper:enrich(field=ProductType)
| groupBy([SHA256String, FileName], function=[
    count(as=NumberOfDetections),
    collect([ReadableTime, SeverityName, DetectName, Tactic, Technique, ComputerName, ProductType, Version], limit=10)
])
| sort(NumberOfDetections, order=desc, limit={int(limit)})
""".strip()


def detection_query(days: int, limit: int = 100) -> str:
    """Query utama untuk ambil detection detail dari NGSIEM.

    Dashboard memakai hasil CrowdStrike sebagai data utama. VirusTotal hanya enrichment lokal.
    Query ini sengaja tetap mengambil SHA256String untuk matching internal, tetapi SHA256 tidak
    ditampilkan di dashboard atau report.
    """
    return f"""
ExternalApiType=Event_EppDetectionSummaryEvent Tactic!=/Custom Intel/i
| ReadableTime := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="Asia/Jakarta")
| timeDelta := now() - @timestamp
| timeDeltaDays := timeDelta/1000/60/60/24
| round(timeDeltaDays)
| timeDeltaDays < {int(days)}
| match(file="aid_master_main.csv", field=[AgentId], column=aid, include=[Version,ProductType], strict=false)
| $falcon/helper:enrich(field=ProductType)
| case {{
    DetectName=/trojan/i OR FileName=/trojan/i
        | ObjectType := "Trojan";
    DetectName=/worm/i OR FileName=/worm/i
        | ObjectType := "Worm";
    DetectName=/ransom/i OR FileName=/ransom/i
        | ObjectType := "Ransomware";
    DetectName=/phish|credential|url/i OR FileName=/^https?:\\/\\//i
        | ObjectType := "Phishing Link";
    DetectName=/script|powershell|command|scripting|macro/i OR FileName=/\\.(ps1|vbs|js|jse|hta|bat|cmd)$/i
        | ObjectType := "Suspicious Script";
    FileName=/\\.(exe|scr|msi)$/i
        | ObjectType := "Executable";
    FileName=/\\.dll$/i OR FileName=/rundll32\\.exe/i
        | ObjectType := "DLL / LOLBIN";
    *
        | ObjectType := "Suspicious Object"
}}
| groupBy([FileName, SHA256String, ObjectType, SeverityName], function=[
    count(as=NumberOfDetections),
    collect([ReadableTime, ComputerName, DetectName, Tactic, Technique, ProductType, Version], limit=10)
])
| sort(NumberOfDetections, order=desc, limit={int(limit)})
""".strip()


FINAL_QUERY_REFERENCE = r'''
ExternalApiType=Event_EppDetectionSummaryEvent Tactic!=/Custom Intel/i
| ReadableTime := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="Asia/Jakarta")
| timeDelta := now() - @timestamp
| timeDeltaDays := timeDelta/1000/60/60/24
| round(timeDeltaDays)
| timeDeltaDays < __DAYS__
| SHA256String=*
| match(file="aid_master_main.csv", field=[AgentId], column=aid, include=[Version,ProductType], strict=false)
| $falcon/helper:enrich(field=ProductType)
| match(file="vt_hash_enrichment.csv", field=[SHA256String], column=SHA256String, include=[VTFound,VTMalicious,VTSuspicious,VTUndetected,VTObjectType,VTThreatLabel], strict=false)
| case {
    VTThreatLabel=/trojan/i
        | ObjectType := "Trojan";
    VTThreatLabel=/worm/i
        | ObjectType := "Worm";
    VTThreatLabel=/ransom/i
        | ObjectType := "Ransomware";
    VTThreatLabel=/phish/i
        | ObjectType := "Phishing";
    VTMalicious > 10
        | ObjectType := "Malware";
    VTObjectType=/script|powershell|batch|javascript|vbs/i
        | ObjectType := "Suspicious Script";
    VTObjectType=/executable|win32|pe/i
        | ObjectType := "Executable";
    DetectName=/trojan/i OR FileName=/trojan/i
        | ObjectType := "Trojan";
    DetectName=/worm/i OR FileName=/worm/i
        | ObjectType := "Worm";
    DetectName=/ransom/i OR FileName=/ransom/i
        | ObjectType := "Ransomware";
    DetectName=/phish|credential|url/i OR FileName=/^https?:\/\//i
        | ObjectType := "Phishing Link";
    DetectName=/script|powershell|command|scripting|macro/i OR FileName=/\.(ps1|vbs|js|jse|hta|bat|cmd)$/i
        | ObjectType := "Suspicious Script";
    FileName=/\.(exe|scr|msi)$/i
        | ObjectType := "Executable";
    FileName=/\.dll$/i OR FileName=/rundll32\.exe/i
        | ObjectType := "DLL / LOLBIN";
    *
        | ObjectType := "Suspicious Object"
}
| groupBy([FileName, SHA256String, ObjectType, SeverityName, VTFound, VTMalicious, VTSuspicious, VTObjectType, VTThreatLabel], function=[
    count(as=NumberOfDetections),
    collect([ReadableTime, ComputerName, DetectName, Tactic, Technique, ProductType, Version], limit=10)
])
| table([
    ReadableTime,
    FileName,
    ObjectType,
    SHA256String,
    SeverityName,
    NumberOfDetections,
    VTFound,
    VTMalicious,
    VTSuspicious,
    VTObjectType,
    VTThreatLabel,
    ComputerName,
    DetectName,
    Tactic,
    Technique,
    ProductType,
    Version
], limit=100)
| sort(NumberOfDetections, order=desc, limit=100)
'''.strip()

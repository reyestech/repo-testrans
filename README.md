# repo-testrans


<div align="center">
  <img src="https://github.com/user-attachments/assets/523985a4-07ce-4084-a36c-52a2243e502e" width="99%" alt="Boss of the SOC"/>
</div>

---

# Splunk: Ransomware Investigation & Response
### Splunk IR Lab — Cerber Ransomware: Detect, Trace, Contain
Hector M. Reyes | SOC Analyst | Boss of the SOC  
[Google Docs | Splunk: Ransomware](https://docs.google.com/document/d/19y3aXtqZZPFv6Lv4ywes7nDzFUVKh1VeDm2lGbytTkc/pub)

<div align="center">
  <img src="https://github.com/user-attachments/assets/aa505c5a-cad1-49ef-96b1-62fa6f2c2272" width="60%" alt="Splunk Ransomware"/>
</div>

---

## TL;DR
- Proved ransomware activity on **we8105desk** by correlating **DNS**, **Suricata**, **Sysmon**, and **Windows Registry** telemetry.  
- Identified the **first suspicious domain**, **encryptor payload** (`mhtr.jpg`), **USB lure** (`MIRANDA_PRI`), **patient-zero IP**, and **file-server impact** (distinct PDFs encrypted).  
- Outcome: an operational **playbook** (detections + queries) for early signal, containment, and recovery.

---

## **Scenario**
Bob Smith’s Windows 10 workstation (**we8105desk**) began blasting audio, changed desktop wallpaper, and locked files—classic **ransomware**. Bob admits plugging in a found USB and opening `Miranda_Tate_unveiled.dotm`. Your job: confirm encryption, trace ingress → payload → spread, and document detection + containment + hardening.

## 📦 Tools Reference
| Category     | Tool / Feature                     | Purpose                                                     |
| ------------ | ---------------------------------- | ----------------------------------------------------------- |
| SIEM         | Splunk                             | Search, detections, evidence timeline                       |
| Sandbox      | Windows Sandbox / Sandboxie-Plus   | Safe inspection of URLs/files                               |
| Threat Intel | VirusTotal / AlienVault OTX        | Hash/domain/IP enrichment                                   |
| Windows      | Sysmon + WinEvent / WinRegistry    | Process/file telemetry; device/USB artifacts                |
| Parsing      | REX / `stats` / `transaction`      | Extract fields; counts; durations                           |

---

## **Pre-Engagement Artifacts**
We safely preview artifacts in a sandbox before hunting in Splunk.
- **Ransomware screenshot**: https://botscontent.netlify.app/v1/cerber-sshot.png  
- **Ransomware voice memo**: https://botscontent.netlify.app/v1/cerber-sample-voice.mp3

<div align="center">
  <img src="https://github.com/user-attachments/assets/9170860e-4d87-461a-ac46-2de721545ddd" width="40%" alt="Ransomware Screen"/>
  <img src="https://github.com/user-attachments/assets/246caec0-34e4-4ee1-839b-20e918704e4c" width="30%" alt="Ransomware Screen 2"/>
</div>

---

## Ransomware 200 — Identify Patient-Zero Host/IP
**Question:** Most likely IPv4 of `we8105desk` on 24-AUG-2016?  
**SPL**
```spl
index=botsv1 host=we8105desk earliest=08/24/2016:00:00:00 latest=08/25/2016:00:00:00
| stats dc(src_ip) as srcs values(src_ip) as ips
```
You can just browse events for that day; confirm src_ip in context.
- [ ] **Answer:** 192.168.250.100
- [ ] 
---

Ransomware 201 — Suricata Signature With Fewest Alerts
SPL

index=botsv1 sourcetype=suricata cerber
| stats count by alert.signature_id
| sort count
| head 1
- [ ] **Answer:**

---
Ransomware 202 — Encryption-Phase FQDN

Question: FQDN Cerber directs the user to during encryption.
SPL

index=botsv1 sourcetype=stream:DNS src_ip=192.168.250.100
| search NOT query=*.local NOT query=*.arpa NOT query=*.microsoft.com NOT query=*.msn.com NOT query=*.info
| table _time query dest_ip
| sort _time
- [ ] **Answer:** cerberhhyed5frqa.xmfir0.win

---

Ransomware 203 — First Suspicious Domain Visited

Use the timeline from 202; the first suspicious domain observed:
- [ ] **Answer:** solidaritedeproximite.org

---

Ransomware 204 — USB Key Name (WinRegistry)
SPL

index=botsv1 sourcetype=winregistry host=we8105desk friendlyname
| table _time host friendlyname data_* registry_path
| sort _time
- [ ] **Answer:** MIRANDA_PRI

---

Ransomware 206 — File Server IPv4
SPL

index=botsv1 sourcetype=winregistry host=we8105desk fileshare
| table _time data_*
- [ ] **Answer:** 192.168.250.20

---

Ransomware 207 — Distinct PDFs Encrypted on File Server
SPL

index=botsv1 host=we9041srv "*.pdf"
| stats dc(Relative_Target_Name) as distinct_pdfs
- [ ] **Answer:** Answer: 526 <!-- adjust if your query returns a different count -->

---

Ransomware 208 — ParentProcessId (VBScript → 121214.tmp)
SPL
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ("*.vbs" OR "121214.tmp")
| table _time host Image ParentImage ProcessId ParentProcessId CommandLine
| sort _time
- [ ] **Answer:**  3968

---

Ransomware 209 — .txt Files Encrypted in Bob’s Profile
SPL
index=botsv1 host=we8105desk sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" \
TargetFilename="C:\\Users\\bob.smith.WAYNECORPINC\\*.txt"
| stats dc(TargetFilename) as distinct_txt
- [ ] **Answer:** Answer: 406 <!-- adjust if your query differs -->

---

Ransomware 210 — Name of Downloaded Cryptor
SPL
index=botsv1 sourcetype=suricata dest_ip="192.168.250.100" "http.hostname"="solidaritedeproximite.org"
| table _time http.uri http.request_body fileinfo.filename
| sort _time
- [ ] **Answer:** mhtr.jpg

---

Ransomware 211 — Likely Obfuscation Technique
Enrich via hash/URL intel; cryptor embedded in an image →
- [ ] **Answer:** Steganography

---

flowchart TD
    A[USB lure opened on we8105desk] --> B[DNS queries incl. suspicious domains]
    B --> C[Suricata alerts / payload delivery (mhtr.jpg)]
    C --> D[Process lineage (VBScript -> 121214.tmp)]
    D --> E[Encryption activity on host profile]
    E --> F[SMB traffic to file server (we9041srv)]
    F --> G[Distinct PDFs encrypted]
    G --> H[Detections & Containment]
    subgraph Splunk Hunt
      B --- C --- D --- E --- F --- G
    end

---

📚 Lessons Learned — Checklist

 Early DNS signals pay off: filtering benign domains exposes the first touchpoints.

 Process lineage matters: parent/child (VBS → TMP) cuts through noise.

 Write-velocity baselines: spikes + new extensions are high-signal.

 Registry is gold for ingress: USB-friendly names confirm the lure.

 Quantify impact: distinct encrypted files guide triage & comms.

 Operationalize: convert queries into saved searches, alerts, and dashboards.

🏁 Conclusion

This lab turns a messy outbreak into a timeline of compromise → containment → hardening. By correlating DNS, Suricata, Sysmon, and Registry artifacts, we identified patient-zero, traced payload delivery, measured impact on the file server, and produced repeatable detections.

The same rhythm applies in production: observe → correlate → validate → harden. Practicing it here builds the muscle memory to respond faster when the stakes are real.

Next: Extend to Risk-Based Alerting (weight DNS + write spikes + lineage) and add SOAR actions for rapid isolation and backup validation.

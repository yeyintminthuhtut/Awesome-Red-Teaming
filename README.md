# Awesome Red Teaming
List of Awesome Red Team / Red Teaming Resources

This list is for anyone wishing to learn about Red Teaming but do not have a starting point.

Anyway, this is a living resources and will update regularly with latest Adversarial Tactics and Techniques.

You can help by sending Pull Requests to add more information.

Table of Contents
=================

 * [Social Engineering](#-social-engineering)
 * [OSINT](#-osint)
 * [Delivery](#-delivery)
 * [Implant Creation](#-implant-creation)
 * [Lateral movement](#-lateral-movement)
 * [Command and Control](#-command-and-control)
 * [Embedded and Peripheral Devices Hacking](#-embedded-and-peripheral-devices-hacking)
 * [Misc](#-misc)
 * [Ebooks](#-ebooks)
 * [Training](#-training--free-)
 * [Certification](#-certification)

## [↑](#table-of-contents) Social Engineering

* [Social Engineer Portal](https://www.social-engineer.org/)
* [7 Best social Engineering attack](http://www.darkreading.com/the-7-best-social-engineering-attacks-ever/d/d-id/1319411)
* [Using Social Engineering Tactics For Big Data Espionage - RSA Conference Europe 2012](https://www.rsaconference.com/writable/presentations/file_upload/das-301_williams_rader.pdf)
* [Weaponizing data science for social engineering: Automated E2E spear phishing on Twitter - Defcon 23](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-WP.pdf)
* [OWASP Presentation of Social Engineering - OWASP](https://www.owasp.org/images/5/54/Presentation_Social_Engineering.pdf)
* [USB Drop Attacks: The Danger of “Lost And Found” Thumb Drives](https://www.redteamsecure.com/usb-drop-attacks-the-danger-of-lost-and-found-thumb-drives/)
* [PyPhishing Toolkit](https://github.com/redteamsecurity/PyPhishing)
* [Best Time to send email](https://coschedule.com/blog/best-time-to-send-email/)

## [↑](#table-of-contents) OSINT

* [Awesome list of OSINT](https://github.com/jivoi/awesome-osint) - A lot of awesome OSINT resources are already covered
* [Reconnaissance using LinkedInt](https://www.mdsec.co.uk/2017/07/reconnaissance-using-linkedint/)


## [↑](#table-of-contents) Delivery

* [Cobalt Strike - Spear Phishing documentation](https://www.cobaltstrike.com/help-spear-phish)
* [Cobalt Strike Blog - What's the go-to phishing technique or exploit?](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* [Spear phishing with Cobalt Strike - Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
* [Phishing Against Protected View](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
* [VEIL-EVASION AES ENCRYPTED HTTPKEY REQUEST: SAND-BOX EVASION](https://cybersyndicates.com/2015/06/veil-evasion-aes-encrypted-httpkey-request-module/)
* [EGRESSING BLUECOAT WITH COBALTSTIKE & LET'S ENCRYPT](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)
* [EMAIL RECONNAISSANCE AND PHISHING TEMPLATE GENERATION MADE SIMPLE](https://cybersyndicates.com/2016/05/email-reconnaissance-phishing-template-generation-made-simple/)
* [An unnecessary addiction to DNS communication](https://blog.cobaltstrike.com/2015/05/14/an-unnecessary-addiction-to-dns-communication/)
* [POWERSHELL EMPIRE STAGERS 1: PHISHING WITH AN OFFICE MACRO AND EVADING AVS](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
* [Phishing with PowerPoint](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
* [PHISHING WITH EMPIRE](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
* [Empire & Tool Diversity: Integration is Key](http://www.sixdub.net/?p=627)


## [↑](#table-of-contents) Implant Creation
* [Exploiting CVE-2017-0199: HTA Handler Vulnerability](https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/)
* [CVE-2017-0199 Toolkit](https://github.com/bhdresh/CVE-2017-0199)
* [CVE-2017-8759-Exploit-sample](https://github.com/vysec/CVE-2017-8759-Exploit-sample)
* [Window Signed Binary](https://github.com/vysec/Windows-SignedBinary)
* [Wepwnise](https://labs.mwrinfosecurity.com/tools/wepwnise/)
* [Bash Bunny](https://hakshop.com/products/bash-bunny)
* [Generate Macro - Tool](https://github.com/enigma0x3/Generate-Macro)
* [How To: Empire’s Cross Platform Office Macro](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
* [Excel macros with PowerShell](https://4sysops.com/archives/excel-macros-with-powershell/)
* [PowerPoint and Custom Actions](https://phishme.com/powerpoint-and-custom-actions/)
* [MS Signed mimikatz in just 3 steps](https://github.com/secretsquirrel/SigThief)
* [Hiding your process from sysinternals](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
* [Luckystrike: An Evil Office Document Generator](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
* [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html)
* [Macro-less Code Exec in MSWord](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [Multi-Platform Macro Phishing Payloads](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
* [Macroless DOC malware that avoids detection with Yara rule](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/)
* [Empire without powershell](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
* [Powershell without Powershell to bypass app whitelist](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
* [Phishing between the app whitelists](https://medium.com/@vivami/phishing-between-the-app-whitelists-1b7dcdab4279)
* [Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files)](http://subt0x10.blogspot.sg/2017/04/bypass-application-whitelisting-script.html)
* [Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations](http://subt0x10.blogspot.sg/2017/04/bypassing-application-whitelisting.html)
* [Windows oneliners to download remote payload and execute arbitrary code](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)
* [Week of Evading Microsoft ATA - Announcement and Day 1 to Day 5](http://www.labofapenetrationtester.com/2017/08/week-of-evading-microsoft-ata-day1.html)
* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks and How Well It Does It](http://www.labofapenetrationtester.com/2016/09/amsi.html)


## [↑](#table-of-contents) Lateral movement
* [Eventvwr File-less UAC Bypass CNA](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
* [Lateral movement using excel application and dcom](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
* [WSH Injection: A Case Study](https://posts.specterops.io/wsh-injection-a-case-study-fd35f79d29dd)
* [Fileless UAC Bypass using sdclt](https://posts.specterops.io/fileless-uac-bypass-using-sdclt-exe-3e9f9ad4e2b3)
* [Bypassing AMSI via COM Server Hijacking](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff)
* [Window 10 Device Guard Bypass](https://github.com/tyranid/DeviceGuardBypasses)
* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
* [OPSEC Considerations for beacon commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [Agentless Post Exploitation](https://blog.cobaltstrike.com/2016/11/03/agentless-post-exploitation/)
* [Windows Access Tokens and Alternate credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [PSAmsi - An offensive PowerShell module for interacting with the Anti-Malware Scan Interface in Windows 10](http://www.irongeek.com/i.php?page=videos/derbycon7/t104-psamsi-an-offensive-powershell-module-for-interacting-with-the-anti-malware-scan-interface-in-windows-10-ryan-cobb)
* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
* [Bringing the hashes home with reGeorg & Empire](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
* [Intercepting passwords with Empire and winning](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
* [Outlook Home Page – Another Ruler Vector](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
* [Outlook Forms and Shells](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
* [Windows Privilege Escalation Checklist](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [A Guide to Configuring Throwback](https://silentbreaksecurity.com/throwback-thursday-a-guide-to-configuring-throwback/)
* [Abusing DNSAdmins privilege for escalation in Active Directory] (http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [Using SQL Server for attacking a Forest Trust](http://www.labofapenetrationtester.com/2017/03/using-sql-server-for-attacking-forest-trust.html)


## [↑](#table-of-contents) Command and Control

* [How to Build a C2 Infrastructure with Digital Ocean – Part 1](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)
* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)
* [Automated Red Team Infrastructure Deployment with Terraform - Part 1](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)
* [6 RED TEAM INFRASTRUCTURE TIPS](https://cybersyndicates.com/2016/11/top-red-team-tips/)
* [Red Teaming for Pacific Rim CCDC 2017](https://bluescreenofjeff.com/2017-05-02-red-teaming-for-pacific-rim-ccdc-2017/)
* [How I Prepared to Red Team at PRCCDC 2015](https://bluescreenofjeff.com/2015-04-15-how-i-prepared-to-red-team-at-prccdc-2015/)
* [Red Teaming for Pacific Rim CCDC 2016](https://bluescreenofjeff.com/2016-05-24-pacific-rim-ccdc_2016/)
* [Randomized Malleable C2 Profiles Made Easy](https://bluescreenofjeff.com/2017-08-30-randomized-malleable-c2-profiles-made-easy/)
* [Cobalt Strike HTTP C2 Redirectors with Apache mod_rewrite - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)
* [High-reputation Redirectors and Domain Fronting](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
* [TOR Fronting – Utilising Hidden Services for Privacy](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
* [Domain Fronting Via Cloudfront Alternate Domains](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* [The PlugBot: Hardware Botnet Research Project](https://www.redteamsecure.com/the-plugbot-hardware-botnet-research-project/)
* [Attack Infrastructure Log Aggregation and Monitoring](https://posts.specterops.io/attack-infrastructure-log-aggregation-and-monitoring-345e4173044e)
* [Finding Frontable Domain](https://github.com/rvrsh3ll/FindFrontableDomains)
* [Apache2Mod Rewrite Setup](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)
* [Empre Domain Fronting](https://www.xorrior.com/Empire-Domain-Fronting/)
* [Domain Hunter](https://github.com/minisllc/domainhunter)
* [Migrating Your infrastructure](https://blog.cobaltstrike.com/2015/10/21/migrating-your-infrastructure/)
* [Redirecting Cobalt Strike DNS Beacons](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
* [Finding Domain frontable Azure domains - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
* [Red Team Insights on HTTPS Domain Fronting Google Hosts Using Cobalt Strike](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
* [Escape and Evasion Egressing Restricted Networks - Tom Steele and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* [Command and Control Using Active Directory](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
* [C2 with twitter](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
* [C2 with DNS](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
* [ICMP C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
* [C2 with Dropbox](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
* [C2 with https](https://pentestlab.blog/2017/10/04/command-and-control-https/)
* [C2 with webdav](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
* [C2 with gmail](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
* [“Tasking” Office 365 for Cobalt Strike C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/)
* [Simple domain fronting PoC with GAE C2 server](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)
* [Using WebDAV features as a covert channel](https://arno0x0x.wordpress.com/2017/09/07/using-webdav-features-as-a-covert-channel/)

## [↑](#table-of-contents) Embedded and Peripheral Devices Hacking
* [Gettting in with the Proxmark3 & ProxBrute](https://www.trustwave.com/Resources/SpiderLabs-Blog/Getting-in-with-the-Proxmark-3-and-ProxBrute/)
* [Practical Guide to RFID Badge copying](https://blog.nviso.be/2017/01/11/a-practical-guide-to-rfid-badge-copying/)
* [Contents of a Physical Pentester Backpack](https://www.tunnelsup.com/contents-of-a-physical-pen-testers-backpack/)
* [MagSpoof - credit card/magstripe spoofer](https://github.com/samyk/magspoof)
* [Wireless Keyboard Sniffer](https://samy.pl/keysweeper/)
* [RFID Hacking with The Proxmark 3](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/)
* [Swiss Army Knife for RFID](https://www.cs.bham.ac.uk/~garciaf/publications/Tutorial_Proxmark_the_Swiss_Army_Knife_for_RFID_Security_Research-RFIDSec12.pdf)
* [Exploring NFC Attack Surface](https://media.blackhat.com/bh-us-12/Briefings/C_Miller/BH_US_12_Miller_NFC_attack_surface_WP.pdf)
* [Outsmarting smartcards](http://gerhard.dekoninggans.nl/documents/publications/dekoninggans.phd.thesis.pdf)
* [Reverse engineering HID iClass Master keys](https://blog.kchung.co/reverse-engineering-hid-iclass-master-keys/)
* [Android Open Pwn Project (AOPP)](https://www.pwnieexpress.com/aopp)

## [↑](#table-of-contents) Misc
* [Red Tips of Vysec](https://github.com/vysec/RedTips)
* [Cobalt Strike Tips for 2016 ccde red teams](https://blog.cobaltstrike.com/2016/02/23/cobalt-strike-tips-for-2016-ccdc-red-teams/)
* [Models for Red Team Operations](https://blog.cobaltstrike.com/2015/07/09/models-for-red-team-operations/)
* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
* [Raphael Mudge - Dirty Red Team tricks](https://www.youtube.com/watch?v=oclbbqvawQg)

## [↑](#table-of-contents) Ebooks
* [Next Generation Red Teaming](https://www.amazon.com/Next-Generation-Teaming-Henry-Dalziel/dp/0128041714)
* [Targeted Cyber Attack](https://www.amazon.com/Targeted-Cyber-Attacks-Multi-staged-Exploits/dp/0128006048)
* [Advanced Penetration Testing: Hacking the World's Most Secure Networks](https://www.amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689)
* [Social Engieers' Playbook Pretical Pretexting](https://www.amazon.com/Social-Engineers-Playbook-Practical-Pretexting/dp/0692306617/ref=as_li_ss_tl?ie=UTF8&linkCode=sl1&tag=talamantesus-20&linkId=37b63c7702c9be6b9f6a1b921c88c8cd)

## [↑](#table-of-contents) Training ( Free )
* [Tradecraft - a course on red team operations](https://www.youtube.com/watch?v=IRpS7oZ3z0o&list=PL9HO6M_MU2nesxSmhJjEvwLhUoHPHmXvz)
* [Advanced Threat Tactics Course & Notes](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/)

## [↑](#table-of-contents) Certification
* [CREST Certified Simulated Attack Specialist](http://www.crest-approved.org/examination/certified-simulated-attack-specialist/)
* [CREST Certified Simulated Attack Manager](http://www.crest-approved.org/examination/certified-simulated-attack-manager/)
* [SEC564: Red Team Operations and Threat Emulation](https://www.sans.org/course/red-team-operations-and-threat-emulation)

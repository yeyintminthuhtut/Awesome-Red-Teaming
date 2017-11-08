# Awesome Red Teaming
一个最好的红队资源清单

此列表同样适用于希望了解红队但没有相关知识储备的人


无论如何，这是一个活跃的列表，会定期更新最新的对抗策略与技术

你可以通过发起 PR 来添加更多有用信息！

目录
=================

 * [社会工程](#社会工程)
 * [OSINT](#-osint)
 * [投递](#投递)
 * [植入](#植入)
 * [横向移动](#横向移动)
 * [命令控制](#命令控制)
 * [嵌入式与物理设备](#嵌入式与物理设备)
 * [杂项](#杂项)
 * [电子书籍](#电子书籍)
 * [培训](#培训)
 * [认证](#认证)

## [↑](#table-of-contents) 社会工程

* [社会工程门户网站](https://www.social-engineer.org/)
* [7 个最好的社会工程攻击案例](http://www.darkreading.com/the-7-best-social-engineering-attacks-ever/d/d-id/1319411)
* [在大数据中使用社会工程策略 - RSA Conference Europe 2012](https://www.rsaconference.com/writable/presentations/file_upload/das-301_williams_rader.pdf)
* [为社会工程武装数据科学：Twitter 中的自动 E2E 鱼叉式网络钓鱼 - Defcon 23](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEFCON-24-Seymour-Tully-Weaponizing-Data-Science-For-Social-Engineering-WP.pdf)
* [OWASP 社会工程介绍 - OWASP](https://www.owasp.org/images/5/54/Presentation_Social_Engineering.pdf)
* [USB 丢失攻击：USB 设备丢失与发现的危险](https://www.redteamsecure.com/usb-drop-attacks-the-danger-of-lost-and-found-thumb-drives/)
* [PyPhishing 工具包](https://github.com/redteamsecurity/PyPhishing)
* [发送电子邮件的最佳时间](https://coschedule.com/blog/best-time-to-send-email/)

## [↑](#table-of-contents) OSINT

* [最好的 OSINT 列表](https://github.com/jivoi/awesome-osint) - 覆盖了很多 OSINT 资源
* [使用 LinkedInt 进行侦察](https://www.mdsec.co.uk/2017/07/reconnaissance-using-linkedint/)


## [↑](#table-of-contents) 投递

* [Cobalt Strike - 鱼叉式网络钓鱼文档](https://www.cobaltstrike.com/help-spear-phish)
* [Cobalt Strike - 什么是钓鱼？如何利用？](https://blog.cobaltstrike.com/2014/12/17/whats-the-go-to-phishing-technique-or-exploit/)
* [使用 Cobalt Strike 进行网络钓鱼- Raphael Mudge](https://www.youtube.com/watch?v=V7UJjVcq2Ao)
* [针对受保护的视图进行钓鱼](https://enigma0x3.net/2017/07/13/phishing-against-protected-view/)
* [VEIL-EVASION 的 AES 加密 HTTPKEY 请求: 沙盒逃逸](https://cybersyndicates.com/2015/06/veil-evasion-aes-encrypted-httpkey-request-module/)
* [EGRESSING BLUECOAT WITH COBALTSTIKE & LET'S ENCRYPT](https://cybersyndicates.com/2016/12/egressing-bluecoat-with-cobaltstike-letsencrypt/)
* [电子邮件侦察与钓鱼邮件模版生成](https://cybersyndicates.com/2016/05/email-reconnaissance-phishing-template-generation-made-simple/)
* [不必依赖 DNS 通信](https://blog.cobaltstrike.com/2015/05/14/an-unnecessary-addiction-to-dns-communication/)
* [POWERSHELL EMPIRE 策略1: 使用 Office 宏指令进行钓鱼与逃避杀软](https://fzuckerman.wordpress.com/2016/10/06/powershell-empire-stagers-1-phishing-with-an-office-macro-and-evading-avs/)
* [使用 PowerPoint 进行钓鱼](https://www.blackhillsinfosec.com/phishing-with-powerpoint/)
* [使用 EMPIRE 进行钓鱼](https://enigma0x3.net/2016/03/15/phishing-with-empire/)
* [Empire 与工具多样性：整合是关键](http://www.sixdub.net/?p=627)


## [↑](#table-of-contents) 植入
* [CVE-2017-0199: HTA 处理漏洞](https://www.mdsec.co.uk/2017/04/exploiting-cve-2017-0199-hta-handler-vulnerability/)
* [CVE-2017-0199 工具包](https://github.com/bhdresh/CVE-2017-0199)
* [CVE-2017-8759 Exploit 示例](https://github.com/vysec/CVE-2017-8759-Exploit-sample)
* [签名 Window 二进制程序](https://github.com/vysec/Windows-SignedBinary)
* [Wepwnise](https://labs.mwrinfosecurity.com/tools/wepwnise/)
* [Bash Bunny](https://hakshop.com/products/bash-bunny)
* [生成宏的工具](https://github.com/enigma0x3/Generate-Macro)
* [Empire 中的跨平台 Office 宏](https://www.blackhillsinfosec.com/empires-cross-platform-office-macro/)
* [使用 PowerShell 执行 Excel 宏](https://4sysops.com/archives/excel-macros-with-powershell/)
* [PowerPoint 与自定义行为](https://phishme.com/powerpoint-and-custom-actions/)
* [三步签名 mimikatz](https://github.com/secretsquirrel/SigThief)
* [在 sysinternals 中隐藏你的进程](https://riscybusiness.wordpress.com/2017/10/07/hiding-your-process-from-sysinternals/)
* [Luckystrike: 邪恶 Office 文档生成器](https://www.shellntel.com/blog/2016/9/13/luckystrike-a-database-backed-evil-macro-generator)
* [被低估的 CSV 注入风险](http://georgemauer.net/2017/10/07/csv-injection.html)
* [MSWord 中无宏代码执行](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/)
* [跨平台宏钓鱼载荷](https://medium.com/@malcomvetter/multi-platform-macro-phishing-payloads-3b688e8eff68)
* [Macroless DOC 恶意软件躲避 Yara 规则](https://furoner.wordpress.com/2017/10/17/macroless-malware-that-avoids-detection-with-yara-rule/amp/)
* [无 Powershell 的 Empire](https://bneg.io/2017/07/26/empire-without-powershell-exe/)
* [无 Powershell 的 Powershell 来绕过应用程序白名单](https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/)
* [应用程序白名单的钓鱼](https://medium.com/@vivami/phishing-between-the-app-whitelists-1b7dcdab4279)
* [绕过应用程序白名单脚本保护 -  Regsvr32.exe 与 COM 脚本(.sct 文件)](http://subt0x10.blogspot.sg/2017/04/bypass-application-whitelisting-script.html)
* [使用 MSBuild.exe 绕过应用程序白名单 - Device Guard 示例与缓解措施](http://subt0x10.blogspot.sg/2017/04/bypassing-application-whitelisting.html)


## [↑](#table-of-contents) 横向移动
* [Eventvwr File-less UAC Bypass CNA](https://www.mdsec.co.uk/2016/12/cna-eventvwr-uac-bypass/)
* [使用 Excel 与 dcom 进行横向移动](https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)
* [WSH 注射案例研究](https://posts.specterops.io/wsh-injection-a-case-study-fd35f79d29dd)
* [Fileless UAC Bypass using sdclt](https://posts.specterops.io/fileless-uac-bypass-using-sdclt-exe-3e9f9ad4e2b3)
* [劫持 COM 服务器绕过 AMSI](https://posts.specterops.io/bypassing-amsi-via-com-server-hijacking-b8a3354d1aff)
* [绕过 Window 10 的 Device Guard](https://github.com/tyranid/DeviceGuardBypasses)
* [My First Go with BloodHound](https://blog.cobaltstrike.com/2016/12/14/my-first-go-with-bloodhound/)
* [OPSEC 有关 beacon command 的注意事项](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [无代理载荷投递](https://blog.cobaltstrike.com/2016/11/03/agentless-post-exploitation/)
* [Windows 访问令牌与备用凭据](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
* [PSAmsi - Windows 10 中与反恶意软件扫描接口交互的进攻性 PowerShell 模块](http://www.irongeek.com/i.php?page=videos/derbycon7/t104-psamsi-an-offensive-powershell-module-for-interacting-with-the-anti-malware-scan-interface-in-windows-10-ryan-cobb)
* [Lay of the Land with BloodHound](http://threat.tevora.com/lay-of-the-land-with-bloodhound/)
* [使用 reGeorg 与 Empire 得到哈希](https://sensepost.com/blog/2016/bringing-the-hashes-home-with-regeorg-empire/)
* [使用 Empire 截取密码](https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/)
* [Outlook 主页 – 另一个攻击向量](https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/)
* [Outlook 的 Form 与 Shell](https://sensepost.com/blog/2017/outlook-forms-and-shells/)
* [Windows 提权清单](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
* [配置回滚指南](https://silentbreaksecurity.com/throwback-thursday-a-guide-to-configuring-throwback/)


## [↑](#table-of-contents) 命令控制

* [使用 Digital Ocean 构建 C2](https://www.blackhillsinfosec.com/build-c2-infrastructure-digital-ocean-part-1/)
* [红队行动的基础设施](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations/)
* [使用 Terraform 进行红队基础设施自动化部署](https://rastamouse.me/2017/08/automated-red-team-infrastructure-deployment-with-terraform---part-1/)
* [6 个红队基础设施的小提示](https://cybersyndicates.com/2016/11/top-red-team-tips/)
* [Pacific Rim CCDC 2017 中的红队](https://bluescreenofjeff.com/2017-05-02-red-teaming-for-pacific-rim-ccdc-2017/)
* [在 PRCCDC 2015 中我是如何进行红队准备的？](https://bluescreenofjeff.com/2015-04-15-how-i-prepared-to-red-team-at-prccdc-2015/)
* [Pacific Rim CCDC 2016 中的红队](https://bluescreenofjeff.com/2016-05-24-pacific-rim-ccdc_2016/)
* [随机化 Malleable 的 C2 配置](https://bluescreenofjeff.com/2017-08-30-randomized-malleable-c2-profiles-made-easy/)
* [使用 Apache 和 mod_rewrite 重定向 Cobalt Strike 的 HTTP C2 - Jeff Dimmock](https://bluescreenofjeff.com/2016-06-28-cobalt-strike-http-c2-redirectors-with-apache-mod_rewrite/)
* [高信誉的重定向与域名前置](https://blog.cobaltstrike.com/2017/02/06/high-reputation-redirectors-and-domain-fronting/)
* [TOR Fronting – 利用隐藏服务保护隐私](https://www.mdsec.co.uk/2017/02/tor-fronting-utilising-hidden-services-for-privacy/)
* [通过 Cloudfront Alternate Domains 部署域名前置](https://www.mdsec.co.uk/2017/02/domain-fronting-via-cloudfront-alternate-domains/)
* [PlugBot: 硬件僵尸网络研究项目](https://www.redteamsecure.com/the-plugbot-hardware-botnet-research-project/)
* [攻击基础设施日志聚合与监视](https://posts.specterops.io/attack-infrastructure-log-aggregation-and-monitoring-345e4173044e)
* [发现前置域名](https://github.com/rvrsh3ll/FindFrontableDomains)
* [安装 Apache2Mod Rewrite](https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup)
* [Empre 域名前置](https://www.xorrior.com/Empire-Domain-Fronting/)
* [域名猎手](https://github.com/minisllc/domainhunter)
* [迁移您的基础设施](https://blog.cobaltstrike.com/2015/10/21/migrating-your-infrastructure/)
* [重定向 Cobalt Strike 的 DNS Beacon](http://www.rvrsh3ll.net/blog/offensive/redirecting-cobalt-strike-dns-beacons/)
* [发现 Azure 中的前置域名 - thoth / Fionnbharr (@a_profligate)](https://theobsidiantower.com/2017/07/24/d0a7cfceedc42bdf3a36f2926bd52863ef28befc.html)
* [对 Google Host 中的 HTTPS 域名前置的红队洞察](https://www.cyberark.com/threat-research-blog/red-team-insights-https-domain-fronting-google-hosts-using-cobalt-strike/)
* [逃出出口受限网络 - Tom Steele and Chris Patten](https://www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks)
* [使用 Active Directory 构建 C2](http://www.harmj0y.net/blog/powershell/command-and-control-using-active-directory/)
* [使用 Twitter 构建 C2](https://pentestlab.blog/2017/09/26/command-and-control-twitter/)
* [使用 DNS 构建 C2](https://pentestlab.blog/2017/09/06/command-and-control-dns/)
* [使用 ICMP 构建 C2](https://pentestlab.blog/2017/07/28/command-and-control-icmp/)
* [使用 Dropbox 构建 C2](https://pentestlab.blog/2017/08/29/command-and-control-dropbox/)
* [使用 HTTPS 构建 C2](https://pentestlab.blog/2017/10/04/command-and-control-https/)
* [使用 webdav 构建 C2](https://pentestlab.blog/2017/09/12/command-and-control-webdav/)
* [使用 Gmail 构建 C2](https://pentestlab.blog/2017/08/03/command-and-control-gmail/)
* [使用 Office 365 的任务用于 Cobalt Strike 的 C2](https://labs.mwrinfosecurity.com/blog/tasking-office-365-for-cobalt-strike-c2/)
* [GAE C2 服务器简单域名前置 PoC](https://www.securityartwork.es/2017/01/31/simple-domain-fronting-poc-with-gae-c2-server/)

## [↑](#table-of-contents) 嵌入式与物理设备
* [从 Proxmark3 与 ProxBrute 开始](https://www.trustwave.com/Resources/SpiderLabs-Blog/Getting-in-with-the-Proxmark-3-and-ProxBrute/)
* [RFID Badge 复制实用指南](https://blog.nviso.be/2017/01/11/a-practical-guide-to-rfid-badge-copying/)
* [一个物理渗透测试人员的背包](https://www.tunnelsup.com/contents-of-a-physical-pen-testers-backpack/)
* [MagSpoof - 信用卡/磁条卡伪造](https://github.com/samyk/magspoof)
* [无线键盘嗅探器](https://samy.pl/keysweeper/)
* [使用 Proxmark 3 进行 RFID 入侵](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/)
* [RFID 的瑞士军刀](https://www.cs.bham.ac.uk/~garciaf/publications/Tutorial_Proxmark_the_Swiss_Army_Knife_for_RFID_Security_Research-RFIDSec12.pdf)
* [探索 NFC 的攻击面](https://media.blackhat.com/bh-us-12/Briefings/C_Miller/BH_US_12_Miller_NFC_attack_surface_WP.pdf)
* [智能卡](http://gerhard.dekoninggans.nl/documents/publications/dekoninggans.phd.thesis.pdf)
* [逆向 HID iClass 的主密钥](https://blog.kchung.co/reverse-engineering-hid-iclass-master-keys/)
* [Android Open Pwn Project (AOPP)](https://www.pwnieexpress.com/aopp)

## [↑](#table-of-contents) 杂项
* [Vysec 的红队技巧](https://github.com/vysec/RedTips)
* [Cobalt Strike 红队技巧 - 2016](https://blog.cobaltstrike.com/2016/02/23/cobalt-strike-tips-for-2016-ccdc-red-teams/)
* [红队行动模型](https://blog.cobaltstrike.com/2015/07/09/models-for-red-team-operations/)
* [红队实践计划](https://github.com/magoo/redteam-plan)
* [Raphael Mudge - 肮脏的红队技巧](https://www.youtube.com/watch?v=oclbbqvawQg)

## [↑](#table-of-contents) 电子书籍
* [下一代红队行动](https://www.amazon.com/Next-Generation-Teaming-Henry-Dalziel/dp/0128041714)
* [针对性网络攻击](https://www.amazon.com/Targeted-Cyber-Attacks-Multi-staged-Exploits/dp/0128006048)
* [高级渗透测试：入侵全球最安全的网络](https://www.amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689)
* [社会工程的手边书](https://www.amazon.com/Social-Engineers-Playbook-Practical-Pretexting/dp/0692306617/ref=as_li_ss_tl?ie=UTF8&linkCode=sl1&tag=talamantesus-20&linkId=37b63c7702c9be6b9f6a1b921c88c8cd)

## [↑](#table-of-contents) 培训（免费）
* [Tradecraft - 关于红队行动的课程](https://www.youtube.com/watch?v=IRpS7oZ3z0o&list=PL9HO6M_MU2nesxSmhJjEvwLhUoHPHmXvz)
* [高级威胁战术课程与笔记](https://blog.cobaltstrike.com/2015/09/30/advanced-threat-tactics-course-and-notes/)

## [↑](#table-of-contents) 认证
* [CREST 模拟攻击专家](http://www.crest-approved.org/examination/certified-simulated-attack-specialist/)
* [CREST 模拟攻击管理员](http://www.crest-approved.org/examination/certified-simulated-attack-manager/)
* [SEC564: 红队行动与威胁仿真](https://www.sans.org/course/red-team-operations-and-threat-emulation)

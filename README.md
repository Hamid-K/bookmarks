# Bookmarks

A bookmark index of useful tools, articles and cheat-sheets useful for various types of projects.

=====================
# Interesting writings and articles:

## WEB:

### PHP

* PHP File Inclusion tips https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/
* Using PHP filter:// for LFI: https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/
* PHP RFI using data:// : https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/
* Preventing XXE in PHP https://websec.io/2012/08/27/Preventing-XEE-in-PHP.html
* Practical PHP object injection https://www.insomniasec.com/downloads/publications/Practical%20PHP%20Object%20Injection.pdf

### JAVA

* https://github.com/frohoff/ysoserial PoC generator for unsafe deserialization vulns
* https://github.com/matthiaskaiser/jmet Java Message Exploitation Tool
* https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities.pdf
* http://www.mcafee.com/us/resources/white-papers/foundstone/wp-pentesters-guide-hacking-activemq-jms-applications.pdf
* https://github.com/OpenSecurityResearch/jmsdigger
* https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true Java UnMarshal bugs


### XXE

* XXE on JSON endpoints https://blog.netspi.com/playing-content-type-xxe-json-endpoints/
* XML/XXE Out-of-Band tricks https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf
* Play framework XXE https://pentesterlab.com/exercises/play_xxe/course


### AMF

* Abusing AMF endpoints as proxy http://blog.gdssecurity.com/labs/2010/3/17/penetrating-intranets-through-adobe-flex-applications.html
* https://github.com/ikkisoft/blazer/blob/master/docs/BH2012_LucaCarettoni_PRESO_FINAL.pdf
* AMF parsing and XXE http://www.agarri.fr/kom/archives/2015/12/17/amf_parsing_and_xxe/index.html
* http://blog.gdssecurity.com/labs/2009/11/11/pentesting-adobe-flex-applications-with-a-custom-amf-client.html
* http://static1.1.sqspcdn.com/static/f/936190/13332467/1311374979537/OWASP_NYNJMetro_Pentesting_Flex.pdf

### Web Misc

* Node.js common issues https://speakerdeck.com/ckarande/top-overlooked-security-threats-to-node-dot-js-web-applications
* Practical HTTP Host header injection http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.htm
* RCE via xstream deserialization http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/
* Hunting asynchronous vulnerablities http://blog.portswigger.net/2015/09/hunting-asynchronous-vulnerabilities.html
* AngularJS interesting tricks http://fr.slideshare.net/x00mario/an-abusive-relationship-with-angularjs
* SQL Injection knowledge base http://websec.ca/kb/sql_injection
* Pentest bookmarks collection http://www.getmantra.com/hackery/
* XSS audit tips http://erlend.oftedal.no/blog/?blogid=127
* various XSS test vectors http://84692bb0df6f30fc0687-25dde2f20b8e8c1bda75aeb96f737eae.r66.cf1.rackcdn.com/--xss.html
* http://www.nosqlmap.net/index.html NoSQL attacks
* http://research.aurainfosec.io/bypassing-saml20-SSO/ SAML SSO XML Signature Attacks
* https://soroush.secproject.com/downloadable/common-security-issues-in-financially-orientated-web-applications-_v1.1.pdf Auditing finance/commerce web applications

### Web Smuggling & Cache Poisoning Attacks

* https://github.com/BishopFox/h2csmuggler HTTP2 upgrade
* https://github.com/0ang3el/websocket-smuggle websocket
* https://regilero.github.io/english/security/2019/10/17/security_apache_traffic_server_http_smuggling/
* https://portswigger.net/web-security/request-smuggling
* https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
* https://portswigger.net/research/practical-web-cache-poisoning
* https://portswigger.net/research/web-cache-entanglement
* https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures
* https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
* https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler
* 


### Misc

* Great cheat-sheet (including *nix LPE tricks) https://book.hacktricks.xyz/linux-unix/privilege-escalation
* Taxonomy of software security errors http://www.hpenterprisesecurity.com/vulncat/en/vulncat/index.html
* playing with VSAT http://2012.hack.lu/archive/2009/Playing%20with%20SAT%201.2%20-%20Hacklu.pdf
* Outlook RCE trick https://medium.com/@networksecurity/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0#.9iiadiu47
* Hacking Cisco ASA (practical vulns) https://ruxcon.org.au/assets/2014/slides/Breaking%20Bricks%20Ruxcon%202014.pdf
* Active-Directory recon without admin rights https://adsecurity.org/?p=2535
* Clang hardening cheat-sheet http://blog.quarkslab.com/clang-hardening-cheat-sheet.html
* Large list of various cheat-sheets (sec related) http://blog.securitymonks.com/2009/08/15/whats-in-your-folder-security-cheat-sheets/
* http://www.cheat-sheets.org/
* http://www.exfiltrated.com/research-BIOS_Based_Rootkits.php
* Analyzing PDF file http://hiddenillusion.blogspot.ca/2013/12/analyzepdf-bringing-dirt-up-to-surface.html 
* https://www.howtoforge.com/how-to-set-up-a-tor-middlebox-routing-all-virtualbox-virtual-machine-traffic-over-the-tor-network
* Post-Exploitation tricks WiKi http://pwnwiki.io/#!index.md
* BGP security assessment http://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf
* IKE-Scan testing wiki https://web.archive.org/web/20150609064941/http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide
* MDM testing must-read https://www.blackhat.com/docs/us-16/materials/us-16-Tan-Bad-For-Enterprise-Attacking-BYOD-Enterprise-Mobile-Security-Solutions-wp.pdf

## Code Audit:
* PHP audit cheat-sheet: https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet
* PHP audit notes https://github.com/80vul/pasc2at
* Various lang./libs cheat-sheets index: https://github.com/detailyang/awesome-cheatsheet
* Perl Jam: Interesting perl notes https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2542/original/the-perl-jam-netanel-rubin-31c3.pdf
* Perl Jam2: https://lab.dsst.io/32c3-slides/7130.html
* Python: List of most of dangerous APIs https://docs.openstack.org/bandit/latest/blacklists/blacklist_calls.html
* https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/ Go lang audit tips
* https://vulncat.fortify.com/en/weakness ref. for many languages 
* https://rules.sonarsource.com/ pretty good and up to date ref for many languages.

* https://securitylab.github.com/events/2020-02-14-offensivecon **Great kick-start workshop for learning CodeQL**
* https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html **CodeQL setup guide for VS Code.**

## Wireless comm
* Sniffing 4.9GHz public safety spectrum https://github.com/Subterfuge-Framework/Subterfuge
* SkyNet http://static.usenix.org/events/woot11/tech/final_files/Reed.pdf
* http://blog.opensecurityresearch.com/2012/06/getting-started-with-gnu-radio-and-rtl.html

## Kubernetes
* https://www.inguardians.com/2018/12/12/attacking-and-defending-kubernetes-bust-a-kube-episode-1/
* https://raesene.github.io/blog/2016/10/08/Kubernetes-From-Container-To-Cluster/
* https://www.youtube.com/watch?v=vTgQLzeBfRU Hacking and Hardening Kubernetes Clusters by Example 
* https://www.youtube.com/watch?time_continue=72&v=1k-GIDXgfLw Good (security) intro into kubernetes
* https://www.youtube.com/watch?v=n9ljS-TQRQE another useful basics intro
* https://www.cisecurity.org/benchmark/kubernetes/ CIS Kubernetes Benchmark v1.4.0

# +Interesting tools:+

## OSINT

### Psssive:

* https://dnsdumpster.com Passive DNS recon
* https://www.passivetotal.org Passive multi-source threats and info gathering (requires subscription)
* https://www.censys.io Internet scan (DNS,SSL,Web,Mail) results search 
* https://scans.io Regularly updated IPv4 space scan raw data 
* http://bgp.he.net/AS23148#_prefixes For discovering all IPs related to targets using BGP. Mix with google dorks.
* https://whois.domaintools.com Extensive reverse-dns lookup (not free for large results)
* http://urlfind.org/ URL and cross-domain mapping
* https://www.virustotal.com/en/search/ Searching domains,emails,IP,strings,...
* Maltego: Multi source/purpose OSINT tool (some modules are not passive!) https://www.paterva.com/web6/products/maltego.php
* Harvester: Gather emails/vhosts/sub-domains using search engines https://github.com/laramies/theHarvester

### Active:

* Fierce: DNS brute-force tool <http://tools.kali.org/information-gathering/fierce>
* TXDNS: Fast DNS brute-force (win) <http://www.vulnerabilityassessment.co.uk/txdns.htm>
* Large hostname dictionary <https://github.com/TheRook/subbrute/blob/master/names.txt>
* FOCA: Extensive passive & active OSINT and meta-data enumeration (win) https://www.elevenpaths.com/labstools/foca/
* SpiderFoot: Python do-over of a great old tool, THE OSIG TOOL to use specially for larger targets and corps. https://github.com/smicallef/spiderfoot

* https://github.com/nahamsec/lazys3 scan AWS instances for a domain

## Web-App assessment tools:

* *Burp-Suite*: Various automated/manual features. Automatic scanner in Pro https://portswigger.net/burp/
* BurpSuite Plugin: AuthMatrix (for testing proper auth implemenations) http://zuxsecurity.blogspot.de/2016/01/authmatrix-for-burp-suite.html
* BurpSuite Plugin: StaticScan (offline JS audit) https://github.com/tomsteele/burpstaticscan
* BurpSuite Plugin: Blazer (AMF Testing) https://github.com/ikkisoft/blazer
* Many other BurpSuite Plugins: https://portswigger.net/bappstore/
* *SoapUI:* Parsing and testing web services, mix with BurpSuite,bur also has some limited security tests (XSS/SQLi/XMLi)  https://www.soapui.org/downloads/soapui.html
* *Arachni-Scanner:* automated web scanner http://www.arachni-scanner.com/
* *W3AF:* Semi-automated web scanner (many useful plugins) http://w3af.org/
* *Dir-Buster:* Fast dir burute-force with extensive dic files https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
* *IIS-ShortName-Scanner:* Abuse IIS misconfig to grab dir/file 8.3 (also possible with Nmap NSE script) names https://github.com/irsdl/IIS-ShortName-Scanner 
* *Nmap --script=http-** Many useful NSE scripts for web-apps and enumeration https://nmap.org/nsedoc/index.html
* *OWASP ZAP:* Similar to Burp (win) https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project
* *Fiddler:* similar to burp and ZAP http://www.telerik.com/fiddler
* *SQLmap:* automated SQLi detect/exploit http://sqlmap.org/
* *SQLninja:* automated SQLi (useful plugins & scripts for win/ms-sql/OOB) http://sqlninja.sourceforge.net/index.html
* *DOMinatorPro:* DOM based attacks tool https://dominator.mindedsecurity.com/
*  *Xcat:* XPath injection tool https://github.com/orf/xcat
* *deblaze:* AMF endpoint enumeration and interaction https://github.com/SpiderLabs/deblaze
* *blazentoo* AMF attack tool for abusing proxy endpoints https://github.com/GDSSecurity/blazentoo
* *JMET* Java serialization attacks payload generator https://github.com/matthiaskaiser/jmet
* *Useful Firefox/Chrome plugins:*
* FireBug: Debugging web pages, scripts, cookies, etc http://getfirebug.com/
* FlashBug: Firebug plugin for auditing flash apps, including decompile
* WebApplyzer: detecting web-app technology https://wappalyzer.com/
* PassiveRecon: detecting web-app technology https://addons.mozilla.org/en-US/firefox/addon/passiverecon/
* User-Agent Switcher: change broswer UA http://chrispederick.com/work/user-agent-switcher/
* FoxyProxy: quickly change to different proxy settings (or use proxy based on pattern matching) https://getfoxyproxy.org/
* Retire.js: auto detect outdated 3rd party JS libs included in the web-app http://bekk.github.io/retire.js/
* List of other interesting plugins http://www.getmantra.com/tools.html

## SAP/ERP:

* ERPScan tools: multiple useful SAP audit tools (mix modules with Burp!) https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/
* Metasploit SAP modules:
* SAPyto: SAP pentest framework https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/
* BizSploit: free/commercial SAP pentest framework https://www.onapsis.com/research/free-solutions
* SAPPy https://github.com/jacebrowning/sappy

## Database (Oracle,MySQL,MSSQL,...)

* Multiple Oracle audit and scan tools to brute/enum/exploit oracle http://www.cqure.net/wp/tools/database/
* AppDetective Pro: Commercial (with trial) extensive vuln-assessment and audit for many DB platforms https://www.trustwave.com/Products/Database-Security/AppDetectivePRO/
* McAfee DSS: commercial (with trial) database vuln-assessment and audit tool http://www.mcafee.com/us/products/security-scanner-for-databases.aspx
* Metasploit modules: many useful brute/enum/exploit modules
* Canvas modules: a number of useful enum/exploit modules
* Nmap NSE: many useful nmap scripts for recon/audit/enum
* MSSQL post-exploitation http://mssqlpostexploit.codeplex.com/
>

## Code audit tools:

* https://securitylab.github.com/tools/codeql **must-learn** semantic code auditing tool for all (supported) languages.
* https://www.jetbrains.com/idea/ IntelliJ IDEA Ultimate IDE: great search/back-trace/debugging features useful during audit
* https://github.com/agelastic/intellij-code-audit/ IntelliJ Java audit policies: extra audit policies for IDEA 
* http://rips-scanner.sourceforge.net RIPS (PHP): Obsolete but still useful static audit (new redesign will be out soon) 
* http://php-grinder.com/
* http://www.devbug.co.uk/
* https://github.com/FloeDesignTechnologies/phpcs-security-audit grep for interesting keywords
* https://github.com/find-sec-bugs/find-sec-bugs Find-Security-Bugs (Java) 
* https://github.com/tomsteele/burpstaticscan Burp Static Scan: auditing JS using burpSuite static-scan engine 
* http://www.downloadcrew.com/article/26642-swfscan HP SWFscan: Automatic decompile and basic audit of flash (obsolete, but useful) 
* http://labs.adobe.com/technologies/swfinvestigator/ Adobe SWFinvestigator: Useful for static/dynamic audit of flash apps 
* https://github.com/nccgroup/VCG/tree/master/VisualCodeGrepper Visual-Code-Grepp useful collection of patterns and keywords(win) C/C++, Java, C#, VB and PL/SQL
* https://dominator.mindedsecurity.com/ DOMinatorPro: DOM based attacks tool 
* http://www.computec.ch/projekte/codex/
* http://marketplace.eclipse.org/content/contrast-eclipse WASP Top 10 detection plugin for Eclipse
* http://code-pulse.com/  code coverage monitoring for blackbox app tests
* http://jshint.com/ JS static code analysis
* https://pmd.github.io classic static code analyzer supporting many langs.
* https://jeremylong.github.io/DependencyCheck/index.html Scans various source & config files and cross-check with CVE DB to report outdated libraries.
* https://nodesecurity.io/opensource NSP scans Node.js applications for outdated modules.
* http://retirejs.github.io/retire.js/ Scans JS/Node codes and applications for outdated modules and libraries
* https://github.com/dpnishant/raptor web-based (web-serivce + UI) github centric source-vulnerability scanner
* https://github.com/presidentbeef/brakeman Ruby on Rails static code scanner
* https://github.com/rubysec/bundler-audit Auditing Ruby  3rd party libs versions
* https://github.com/rubygarage/inquisition Ruby auditing tools gem
* https://github.com/thesp0nge/dawnscanner Ruby applications security scanner
* https://github.com/antitree/manitree Android  Apps manifest.xml audit
* https://github.com/Microsoft/DevSkim/ Visual-Stuudio/Code plugin with base rules for highlighting (C#, C++, JS, SQL, ...) issues.
* https://www.nuget.org/packages/SafeNuGet/ Scans 3rd party libs used in .Net apps for known issues. Also bundles with VS.
* https://www.viva64.com/en/pvs-studio/ Static code (security) analysis, also bundles with VS.
* https://github.com/PyCQA/bandit Static code (security) analysis for Python. Extendable with plugins.
* https://requires.io Automatic check of Python pip package versions against known vulns. Create a repo with required.pip list on github and point the site to it.
* https://pyup.io/safety/ checks requirements.txt for outdated and vulnerable imports
* https://github.com/fkie-cad/cwe_checker ELF static analyser based on BAD (Intel/ARM/MIPS/PPC, +IDA/Ghidra
* https://pyre-check.org/ Python lib for taint analysis via sinks.
* https://github.com/security-code-scan/security-code-scan C# audit tool (like FindSecBugs for java).
* https://xxxx.immunityinc.com/consultingresearch/code-graph-auditor-intellij-plugin Code-Graph-Auditor for IDEA (internal tool)
* https://semgrep.dev/ multi-language AST powered audit tool with easy to use rule syntax. (Good CodeQL alternative)

## Android/iOS audit tools & checklists:

* https://github.com/iSECPartners/LibTech-Auditing-Cheatsheet
* https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet
* https://github.com/MobSF/Mobile-Security-Framework-MobSF Detailed audit of APK files for config/security issues
* https://github.com/AndroBugs/AndroBugs_Framework quick static analysis of apk files
* https://github.com/ashishb/android-security-awesome collection of android sec. related tools list
* https://www.owasp.org/index.php/Android_Testing_Cheat_Sheet
* https://www.ostorlab.co/ Online app analysis sandbox & static analysis
* http://sanddroid.xjtu.edu.cn/ Online app analysis sandbox & static analysis
* https://github.com/sensepost/objection Frida based framework for iOS/Android (+auto resign & deploy apps)
* https://github.com/chaitin/passionfruit Frida based framework for iOS
* https://github.com/nccgroup/house Frida based framework for Android, similar to PassionFruit
* https://github.com/linkedin/qark Android app review kit
* https://github.com/vtky/Swizzler2 Frida based toolkit for testing iOS/Android apps and MDM solutions
* https://github.com/JesusFreke/smali Android DEX format (.smali files) [dis]assembler
* https://github.com/AloneMonkey/frida-ios-dump pull decrypted IPA from jailbroken iOS
* https://github.com/ay-kay/cda cmd tool to search/list installed iOS apps and details
* https://github.com/NitinJami/keychaineditor iOS keychain dump/edit on jailbroken devices
* https://github.com/ptoomey3/Keychain-Dumper iOS keychain dumper
* https://github.com/nowsecure/node-applesign NodeJS tool for easy re-sign of iOS apps
* https://github.com/dweinstein/awesome-frida Awesome Frida based tools/libs/resources
* https://tinyhack.com/2018/02/05/pentesting-obfuscated-android-app/ Deobfuscate Android apps

## Wireless/BlueTooth/RFID/etc.

* Live RFID hacking distro http://www.openpcd.org/Live_RFID_Hacking_System
* automated WPS exploit script https://github.com/derv82/wifite
* https://github.com/OpenSecurityResearch/hostapd-wpe
* https://www.kismetwireless.net/kisbee/ Zigbee open-source hardware
* https://www.kismetwireless.net/android-pcap/ 802.11 capturing for andorid
* https://github.com/SecUpwN/Android-IMSI-Catcher-Detector
* https://www.adafruit.com/product/1497
* http://www.p1sec.com/corp/research/tools/sctpscan/
* http://www.shellntel.com/blog/2015/9/23/assessing-enterprise-wireless-networks crEAP - Harvesting Users on Enterprise Wireless Networks
* https://n0where.net/wps-attack-tool-penetrator-wps/
* https://github.com/conorpp/btproxy Bluetooth MiTM proxy
* https://github.com/omriiluz/NRF24-BTLE-Decoder
* https://github.com/riverloopsec/killerbee ZigBee attack framework
* https://github.com/sophron/wifiphisher phishing against wifi clients
* https://github.com/samyk/keysweeper sniffing wireless keyboards
* https://github.com/JiaoXianjun/LTE-Cell-Scanner
* https://github.com/sharebrained/portapack-hackrf HackRF LCD display
* https://github.com/2b-as/xgoldmon  convert USB debug logsphones with XGold baseband processor back to the GSM/UMTS
* http://www.silca.biz/en/products/key-replacement-business/residential-remotes/916270/remotes-air4.html Device to clone door remotes 
* http://www.rmxlabs.ru/products/keymaster_pro_4_rf/ device to clone LF (125KHz) RFID tags
* http://www.fortresslock.co.uk/welcome/trade-area/smartcard-deluxe-2/ similar to above, in EU market.
* http://www.bishopfox.com/resources/tools/rfid-hacking/attack-tools/ Longer range LF tag cloner (3 feet), easy to build.
* http://www.d-logic.net/nfc-rfid-reader-sdk/products/nfc-usb-stick-dl533n NFC/RFID (HF) USB dungle + Android app

## Hardware hacking

* BusPirate http://dangerousprototypes.com/docs/Bus_Pirate
* JTAGulator http://www.grandideastudio.com/portfolio/jtagulator/
* BinWalk https://github.com/devttys0/binwalk
* Firmware-Mod-Kit https://code.google.com/archive/p/firmware-mod-kit/
* http://firmware.re/
* https://github.com/adamcaudill/Psychson  BadUSB poc
* https://www.pjrc.com/teensy/
* http://rada.re/r/ Reversing MIPS
* https://www.yoctoproject.org/tools-resources  MIPS/ARM emulator
* http://int3.cc/products/facedancer21
* http://int3.cc/products/osprey

## Kubernetes
* https://github.com/cyberark/KubiScan Tools for auditing master node configs
* https://github.com/aquasecurity/kube-hunter Tools for remote test of clusters for common issues
* https://github.com/aquasecurity/kube-bench Tool for local audit of pod/master nodes against CIS benchamrk
* https://github.com/nccgroup/kube-auto-analyzer Tool for local audit of pod/master nodes, can also deploy agent

## VPN

* https://github.com/royhills/ike-scan
* https://github.com/SpiderLabs/ikeforce
* https://github.com/interspective/bike-scan
* https://github.com/historypeats/psikeo

## VoIP

* https://github.com/fozavci/viproy-voipkit
* http://www.voipsa.org/Resources/tools.php Directory of good tools for VoIP hacking

## Chrome Extensions
* Basics https://developer.chrome.com/extensions/overview#arch
* https://www.chromium.org/Home/chromium-security/education/security-tips-for-crx-and-apps
* http://resources.infosecinstitute.com/owned-by-chrome-extensions/#gref
* http://kyleosborn.com/bh2012/advanced-chrome-extension-exploitation-WHITEPAPER.pdf
* Insecure Messaging issues like https://bugs.chromium.org/p/project-zero/issues/detail?id=1527&desc=2#maincol
* https://github.com/koto/xsschef
* Use Node/JS module scanners like NSP and SNYK (https://snyk.io/) against source

## AWS, Azur, etc.
* https://github.com/SecurityFTW/cs-suite Automated auditing of AWS/GCP/Azure
* https://github.com/cyberark/SkyArk Identify & audit privileged entities in Azure and AWS
* https://github.com/nccgroup/Scout2 AWS Audit tool by NCC (recommended)
* https://github.com/sa7mon/S3Scanner Finds & dumps open S3 buckets
* https://github.com/jordanpotti/AWSBucketDump 
* https://github.com/dagrz/aws_pwn AWS testing scripts
* https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation AWS priv-escalation (text)
* https://github.com/DenizParlak/Zeus AWS auditing & hardening tool
* https://github.com/FSecureLABS/awspx Graph-based visualising effective access & resource relationships in AWS
* https://github.com/Ucnt/aws-s3-downloader Downloading S3 buckets
* Check Burp-Suite store for AWS/Azure related extensions. Good stuff there too.

## Linux LPE/Audit
* https://gtfobins.github.io/
* https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite Bash script finding common LPE vectors
* https://github.com/sleventyeleven/linuxprivchecker Python script finding common LPE vectors
* https://github.com/CISOfy/lynis *nix local auidit/test/hardening tool in Bash. 

## Win LPE/Audit
* https://www.kitploit.com/2020/10/patchchecker-web-based-check-for.html quick check for missing patches for LPE
* https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
## Misc

* Smartphone pentest framework http://www.bulbsecurity.com/smartphone-pentest-framework/
* OCSP Client Tool http://www.ascertia.com/products/ocsp-client-tool
* JSmartCardExplorer https://www.primianotucci.com/os/smartcard-explorer
* Mimikatz http://blog.gentilkiwi.com/mimikatz
* Bettercap sniffer https://www.bettercap.org/
* Subterfuge MiTM framework https://github.com/Subterfuge-Framework/Subterfuge
* .Net Reflector: decompiler http://www.red-gate.com/products/dotnet-development/reflector/
* Zanti mobile pentest framework https://www.zimperium.com/zanti-mobile-penetration-testing
* https://www.christophertruncer.com/veil-a-payload-generator-to-bypass-antivirus/
* Malloy: TCP/UDP proxy http://intrepidusgroup.com/insight/mallory/
* GNU tools for win32 https://github.com/bmatzelle/gow/wiki
* Window console emulator https://conemu.github.io/
* DVBsnoop http://dvbsnoop.sourceforge.net/
* Introspy-IOS: IOS app profiling tool https://github.com/iSECPartners/Introspy-iOS
* http://www.frida.re/
* Decompile and view RPC info http://rpcview.org/
* https://www.bro.org/ network monitoring and traffic analysis
* https://github.com/mikispag/rosettaflash Rosetta Flash (CVE-2014-4671)
* http://mitmproxy.org/ MiTM proxy tool
* Pytbull: IDS/IPS testing tool http://pytbull.sourceforge.net/
* Fakenet: dynamic malware behaviour analysis http://pytbull.sourceforge.net/
* PowerSploit: Powershell based exploit framework https://github.com/mattifestation/PowerSploit
* http://x64dbg.com/#start
* https://thesprawl.org/projects/ida-sploiter/
* https://github.com/robertdavidgraham/masscan fast nmap alternative
* https://github.com/coresecurity/impacket python lib for packet generation of multiple protocols
* http://pentestmonkey.net/tools/windows-privesc-check finds weak permissions on win for priv-escalation
* https://github.com/iSECPartners/ios-ssl-kill-switch disable SSL cert validation in IOS
* https://retdec.com/ online binary decompiler (Intel x86, ARM, ARM+Thumb, MIPS, PIC32, PowerPC)
* http://goaccess.io/screenshots Apache log analysis and monitor
* https://www.onlinedisassembler.com/odaweb/
* http://www.reconstructer.org/ Office doc malware scanner 
* https://getgophish.com/ phishing framework
* http://salmanarif.bitbucket.org/visual/index.html ARM visual emulator
* https://github.com/giMini/PowerMemory/tree/master/RWMC Powershell - Reveal Windows Memory Credentials
* https://launchpad.net/~pi-rho/+archive/ubuntu/security debian PPA for common sec. tools
* https://zmap.io/ fast port scanner for scanning entire internet
* http://www.computec.ch/projekte/vulscan/?s=download  Vuln-scanner using NSE for Nmap (cross checking banners with CVEs)
* https://code.google.com/archive/p/smtp-security-scanner/
* https://github.com/proteansec/fuzzyftp simple FTP fuzzer
* http://www.xplico.org/  Network traffic forensics tool
* https://emcinformation.com/283102/REG/.ashx?reg_src=web NetWitness Investigator: powerful network traffic analysis tool
* https://www.bsk-consulting.de/apt-scanner-thor/ interesting anomaly based malware detection
* https://github.com/lanjelot/patator Python multi-protocol bruteforce script (using with Innuendo?)
* https://github.com/nccgroup/BinProxy Proxy tool for (binary) TCP connections. Supports SSL/TLS.

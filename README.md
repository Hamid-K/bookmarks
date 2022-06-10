# Bookmarks

A bookmark index of useful tools, articles and cheat-sheets useful for various types of projects.


# Interesting writings and articles:

## Hamid's Bookmarks:

## WEB:

### PHP

* PHP File Inclusion tips [https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/)
* Using PHP filter:// for LFI: [https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/)
* PHP RFI using data:// : [https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/](https://www.idontplaydarts.com/2011/03/php-remote-file-inclusion-command-shell-using-data-stream/)
* Preventing XXE in PHP [https://websec.io/2012/08/27/Preventing-XEE-in-PHP.html](https://websec.io/2012/08/27/Preventing-XEE-in-PHP.html)
* Practical PHP object injection [https://www.insomniasec.com/downloads/publications/Practical%20PHP%20Object%20Injection.pdf](https://www.insomniasec.com/downloads/publications/Practical%20PHP%20Object%20Injection.pdf)

### JAVA

* [https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial) PoC generator for unsafe deserialization vulns
* [https://github.com/matthiaskaiser/jmet](https://github.com/matthiaskaiser/jmet) Java Message Exploitation Tool
* [https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Kaiser-Pwning-Your-Java-Messaging-With-Deserialization-Vulnerabilities.pdf)
* [http://www.mcafee.com/us/resources/white-papers/foundstone/wp-pentesters-guide-hacking-activemq-jms-applications.pdf](http://www.mcafee.com/us/resources/white-papers/foundstone/wp-pentesters-guide-hacking-activemq-jms-applications.pdf)
* [https://github.com/OpenSecurityResearch/jmsdigger](https://github.com/OpenSecurityResearch/jmsdigger)
* [https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf?raw=true) Java UnMarshal bugs
* [https://github.com/pyn3rd/Spring-Boot-Vulnerability](https://github.com/pyn3rd/Spring-Boot-Vulnerability) Multiple Spring RCE bugs in summary

**RUBY**

*  [http://www.phrack.org/issues/69/12.html](http://www.phrack.org/issues/69/12.html) (must-read paper!)
* [https://github.com/rubysec/bundler-audit#readme](https://github.com/rubysec/bundler-audit#readme)
* [https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Command_Injection](https://www.owasp.org/index.php/Ruby_on_Rails_Cheatsheet#Command_Injection)
* [http://rails-sqli.org/](http://rails-sqli.org/)
* [http://brakemanscanner.org/](http://brakemanscanner.org/)
* [http://guides.rubyonrails.org/security.html](http://guides.rubyonrails.org/security.html)
* [http://weblog.rubyonrails.org/2011/6/8/potential-xss-vulnerability-in-ruby-on-rails-applications/](http://weblog.rubyonrails.org/2011/6/8/potential-xss-vulnerability-in-ruby-on-rails-applications/)
* [https://github.com/bbatsov/rubocop](https://github.com/bbatsov/rubocop)
* [https://github.com/thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner)
* [https://deepsource.io/blog/ruby-security-pitfalls/](https://deepsource.io/blog/ruby-security-pitfalls/)
* [https://blog.codacy.com/ruby-security-issues-you-should-avoid/](https://blog.codacy.com/ruby-security-issues-you-should-avoid/)
* [https://blog.securityinnovation.com/blog/2015/05/ruby-on-rails.html](https://blog.securityinnovation.com/blog/2015/05/ruby-on-rails.html)
* [https://kmarks2013.medium.com/5-common-rails-security-vulnerabilities-58d39be9a270](https://kmarks2013.medium.com/5-common-rails-security-vulnerabilities-58d39be9a270)
* [https://hackerone.com/vakzz?type=user](https://hackerone.com/vakzz?type=user)\]([https://hackerone.com/vakzz?type=user](https://hackerone.com/vakzz?type=user)
* [https://github.com/rapid7/rex-text](https://github.com/rapid7/rex-text)
* [https://docs.rubocop.org/rubocop/cops_security.html](https://docs.rubocop.org/rubocop/cops_security.html)
* ### Static analysis:
* [https://rules.sonarsource.com/ruby/](https://rules.sonarsource.com/ruby/)
* [https://semgrep.dev/p/ruby](https://semgrep.dev/p/ruby)
* [https://brakemanscanner.org/docs/warning_types/](https://brakemanscanner.org/docs/warning_types/)
* ###RCE via Indirections
* Check the related section (2.3.3) from the Phrack article for details.
  * send()
  * \_\_send\_\_()
  * public_send()
  * try()
* ### RCE via Unsafe Reflection
* [http://gavinmiller.io/2016/the-safesty-way-to-constantize/](http://gavinmiller.io/2016/the-safesty-way-to-constantize/)
* [https://blog.convisoappsec.com/en/exploiting-unsafe-reflection-in-rubyrails-applications/](https://blog.convisoappsec.com/en/exploiting-unsafe-reflection-in-rubyrails-applications/)
* [https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/](https://www.praetorian.com/blog/ruby-unsafe-reflection-vulnerabilities/)
* ### RCE via deserialization
* [https://portswigger.net/daily-swig/ruby-taken-off-the-rails-by-deserialization-exploit](https://portswigger.net/daily-swig/ruby-taken-off-the-rails-by-deserialization-exploit)
* [https://www.elttam.com/blog/ruby-deserialization/#content](https://www.elttam.com/blog/ruby-deserialization/#content)
* [https://lab.wallarm.com/exploring-de-serialization-issues-in-ruby-projects-801e0a3e5a0a/](https://lab.wallarm.com/exploring-de-serialization-issues-in-ruby-projects-801e0a3e5a0a/)
* [https://ruby-doc.org/core-2.7.0/Marshal.html#module-Marshal-label-Security+considerations](https://ruby-doc.org/core-2.7.0/Marshal.html#module-Marshal-label-Security+considerations)
* [https://www.zerodayinitiative.com/blog/2019/6/20/remote-code-execution-via-ruby-on-rails-active-storage-insecure-deserialization](https://www.zerodayinitiative.com/blog/2019/6/20/remote-code-execution-via-ruby-on-rails-active-storage-insecure-deserialization)
* [https://book.hacktricks.xyz/pentesting-web/deserialization#ruby](https://book.hacktricks.xyz/pentesting-web/deserialization#ruby)
* [https://codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained/](https://codeclimate.com/blog/rails-remote-code-execution-vulnerability-explained/)
* ###RCE via ERB Template Injection
* [https://www.trustedsec.com/blog/rubyerb-template-injection/](https://www.trustedsec.com/blog/rubyerb-template-injection/)
* [https://blog.appsignal.com/2019/03/26/object-marshalling-in-ruby.html](https://blog.appsignal.com/2019/03/26/object-marshalling-in-ruby.html)
* ### Metasploit:
* [https://www.gushiciku.cn/pl/pit4/zh-tw](https://www.gushiciku.cn/pl/pit4/zh-tw)
* ### Cmdi
* [https://systemtek.co.uk/2019/08/nokogiri-ruby-kernel-open-method-command-injection-vulnerability-cve-2019-5477/](https://systemtek.co.uk/2019/08/nokogiri-ruby-kernel-open-method-command-injection-vulnerability-cve-2019-5477/)
* ### Path traversal
* [https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)
* [https://github.com/mpgn/CVE-2018-3760](https://github.com/mpgn/CVE-2018-3760)
* [https://xz.aliyun.com/t/2542](https://xz.aliyun.com/t/2542)
* [https://groups.google.com/g/ruby-security-ann/c/2S9Pwz2i16k](https://groups.google.com/g/ruby-security-ann/c/2S9Pwz2i16k)
* [https://github.com/mpgn/CVE-2019-5418](https://github.com/mpgn/CVE-2019-5418)

### XXE

* XXE on JSON endpoints [https://blog.netspi.com/playing-content-type-xxe-json-endpoints/](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
* XML/XXE Out-of-Band tricks [https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
* Play framework XXE [https://pentesterlab.com/exercises/play_xxe/course](https://pentesterlab.com/exercises/play_xxe/course)

### AMF

* Abusing AMF endpoints as proxy [http://blog.gdssecurity.com/labs/2010/3/17/penetrating-intranets-through-adobe-flex-applications.html](http://blog.gdssecurity.com/labs/2010/3/17/penetrating-intranets-through-adobe-flex-applications.html)
* [https://github.com/ikkisoft/blazer/blob/master/docs/BH2012_LucaCarettoni_PRESO_FINAL.pdf](https://github.com/ikkisoft/blazer/blob/master/docs/BH2012_LucaCarettoni_PRESO_FINAL.pdf)
* AMF parsing and XXE [http://www.agarri.fr/kom/archives/2015/12/17/amf_parsing_and_xxe/index.html](http://www.agarri.fr/kom/archives/2015/12/17/amf_parsing_and_xxe/index.html)
* [http://blog.gdssecurity.com/labs/2009/11/11/pentesting-adobe-flex-applications-with-a-custom-amf-client.html](http://blog.gdssecurity.com/labs/2009/11/11/pentesting-adobe-flex-applications-with-a-custom-amf-client.html)
* [http://static1.1.sqspcdn.com/static/f/936190/13332467/1311374979537/OWASP_NYNJMetro_Pentesting_Flex.pdf](http://static1.1.sqspcdn.com/static/f/936190/13332467/1311374979537/OWASP_NYNJMetro_Pentesting_Flex.pdf)

### WAF & Bypass methods

* [https://jlajara.gitlab.io/web/2020/02/19/Bypass_WAF_Unicode.html](https://jlajara.gitlab.io/web/2020/02/19/Bypass_WAF_Unicode.html)
* [https://github.com/pyn3rd/WAF-bypass/blob/master/Tala-Security.pdf](https://github.com/pyn3rd/WAF-bypass/blob/master/Tala-Security.pdf)
* [https://github.com/pyn3rd/WAF-bypass/blob/master/KCon_2019_WAF.pdf](https://github.com/pyn3rd/WAF-bypass/blob/master/KCon_2019_WAF.pdf)
* [https://www.slideshare.net/SoroushDalili/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour](https://www.slideshare.net/SoroushDalili/waf-bypass-techniques-using-http-standard-and-web-servers-behaviour)
* [https://soroush.secproject.com/blog/2019/05/x-up-devcap-post-charset-header-in-aspnet-to-bypass-wafs-again/](https://soroush.secproject.com/blog/2019/05/x-up-devcap-post-charset-header-in-aspnet-to-bypass-wafs-again/)
* [https://github.com/irsdl/httpninja](https://github.com/irsdl/httpninja)
* [https://github.com/0xInfection/Awesome-WAF#known-bypasses](https://github.com/0xInfection/Awesome-WAF#known-bypasses)
* [http://news.shamcode.ru/blog/0xinfection--awesome-waf/#known-bypasses](http://news.shamcode.ru/blog/0xinfection--awesome-waf/#known-bypasses)
* [https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0)

### Web Misc

* Node.js common issues [https://speakerdeck.com/ckarande/top-overlooked-security-threats-to-node-dot-js-web-applications](https://speakerdeck.com/ckarande/top-overlooked-security-threats-to-node-dot-js-web-applications)
* Practical HTTP Host header injection [http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.htm](http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.htm)
* RCE via xstream deserialization [http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
* Hunting asynchronous vulnerablities [http://blog.portswigger.net/2015/09/hunting-asynchronous-vulnerabilities.html](http://blog.portswigger.net/2015/09/hunting-asynchronous-vulnerabilities.html)
* AngularJS interesting tricks [http://fr.slideshare.net/x00mario/an-abusive-relationship-with-angularjs](http://fr.slideshare.net/x00mario/an-abusive-relationship-with-angularjs)
* SQL Injection knowledge base [http://websec.ca/kb/sql_injection](http://websec.ca/kb/sql_injection)
* Pentest bookmarks collection [http://www.getmantra.com/hackery/](http://www.getmantra.com/hackery/)
* XSS audit tips [http://erlend.oftedal.no/blog/?blogid=127](http://erlend.oftedal.no/blog/?blogid=127)
* various XSS test vectors [http://84692bb0df6f30fc0687-25dde2f20b8e8c1bda75aeb96f737eae.r66.cf1.rackcdn.com/--xss.html](http://84692bb0df6f30fc0687-25dde2f20b8e8c1bda75aeb96f737eae.r66.cf1.rackcdn.com/--xss.html)
* [http://www.nosqlmap.net/index.html](http://www.nosqlmap.net/index.html) NoSQL attacks
* [http://research.aurainfosec.io/bypassing-saml20-SSO/](http://research.aurainfosec.io/bypassing-saml20-SSO/) SAML SSO XML Signature Attacks
* [https://soroush.secproject.com/downloadable/common-security-issues-in-financially-orientated-web-applications-_v1.1.pdf](https://soroush.secproject.com/downloadable/common-security-issues-in-financially-orientated-web-applications-_v1.1.pdf) Auditing finance/commerce web applications
* [https://github.com/0xn0ne/weblogicScanner](https://github.com/0xn0ne/weblogicScanner) Scanner/PoC for all recent Weblogic RCEs
* [https://github.com/0xn0ne/Middleware-Vulnerability-detection](https://github.com/0xn0ne/Middleware-Vulnerability-detection) check/PoC for various middleware frameworks

### Web Smuggling & Cache Poisoning Attacks

* [https://github.com/BishopFox/h2csmuggler](https://github.com/BishopFox/h2csmuggler) HTTP2 upgrade
* [https://github.com/0ang3el/websocket-smuggle](https://github.com/0ang3el/websocket-smuggle) websocket
* [https://regilero.github.io/english/security/2019/10/17/security_apache_traffic_server_http_smuggling/](https://regilero.github.io/english/security/2019/10/17/security_apache_traffic_server_http_smuggling/)
* [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
* [https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [https://portswigger.net/research/practical-web-cache-poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
* [https://portswigger.net/research/web-cache-entanglement](https://portswigger.net/research/web-cache-entanglement)
* [https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures)
* [https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning)
* [https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler](https://portswigger.net/research/breaking-the-chains-on-http-request-smuggler)
* 

### Misc

* Great cheat-sheet (including \*nix LPE tricks) [https://book.hacktricks.xyz/linux-unix/privilege-escalation](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
* Taxonomy of software security errors [http://www.hpenterprisesecurity.com/vulncat/en/vulncat/index.html](http://www.hpenterprisesecurity.com/vulncat/en/vulncat/index.html)
* playing with VSAT [http://2012.hack.lu/archive/2009/Playing%20with%20SAT%201.2%20-%20Hacklu.pdf](http://2012.hack.lu/archive/2009/Playing%20with%20SAT%201.2%20-%20Hacklu.pdf)
* Outlook RCE trick [https://medium.com/@networksecurity/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0#.9iiadiu47](https://medium.com/@networksecurity/oleoutlook-bypass-almost-every-corporate-security-control-with-a-point-n-click-gui-37f4cbc107d0#.9iiadiu47)
* Hacking Cisco ASA (practical vulns) [https://ruxcon.org.au/assets/2014/slides/Breaking%20Bricks%20Ruxcon%202014.pdf](https://ruxcon.org.au/assets/2014/slides/Breaking%20Bricks%20Ruxcon%202014.pdf)
* Active-Directory recon without admin rights [https://adsecurity.org/?p=2535](https://adsecurity.org/?p=2535)
* Clang hardening cheat-sheet [http://blog.quarkslab.com/clang-hardening-cheat-sheet.html](http://blog.quarkslab.com/clang-hardening-cheat-sheet.html)
* Large list of various cheat-sheets (sec related) [http://blog.securitymonks.com/2009/08/15/whats-in-your-folder-security-cheat-sheets/](http://blog.securitymonks.com/2009/08/15/whats-in-your-folder-security-cheat-sheets/)
* [http://www.cheat-sheets.org/](http://www.cheat-sheets.org/)
* [http://www.exfiltrated.com/research-BIOS_Based_Rootkits.php](http://www.exfiltrated.com/research-BIOS_Based_Rootkits.php)
* Analyzing PDF file [http://hiddenillusion.blogspot.ca/2013/12/analyzepdf-bringing-dirt-up-to-surface.html](http://hiddenillusion.blogspot.ca/2013/12/analyzepdf-bringing-dirt-up-to-surface.html)
* [https://www.howtoforge.com/how-to-set-up-a-tor-middlebox-routing-all-virtualbox-virtual-machine-traffic-over-the-tor-network](https://www.howtoforge.com/how-to-set-up-a-tor-middlebox-routing-all-virtualbox-virtual-machine-traffic-over-the-tor-network)
* Post-Exploitation tricks WiKi [http://pwnwiki.io/#!index.md](http://pwnwiki.io/#!index.md)
* BGP security assessment [http://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf](http://www.blackhat.com/presentations/bh-usa-03/bh-us-03-convery-franz-v3.pdf)
* IKE-Scan testing wiki [https://web.archive.org/web/20150609064941/http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide](https://web.archive.org/web/20150609064941/http://www.nta-monitor.com/wiki/index.php/Ike-scan_User_Guide)
* MDM testing must-read [https://www.blackhat.com/docs/us-16/materials/us-16-Tan-Bad-For-Enterprise-Attacking-BYOD-Enterprise-Mobile-Security-Solutions-wp.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Tan-Bad-For-Enterprise-Attacking-BYOD-Enterprise-Mobile-Security-Solutions-wp.pdf)

## Code Audit:

* PHP audit cheat-sheet: [https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet](https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet)
* PHP audit notes [https://github.com/80vul/pasc2at](https://github.com/80vul/pasc2at)
* Various lang./libs cheat-sheets index: [https://github.com/detailyang/awesome-cheatsheet](https://github.com/detailyang/awesome-cheatsheet)
* Perl Jam: Interesting perl notes [https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2542/original/the-perl-jam-netanel-rubin-31c3.pdf](https://events.ccc.de/congress/2014/Fahrplan/system/attachments/2542/original/the-perl-jam-netanel-rubin-31c3.pdf)
* Perl Jam2: [https://lab.dsst.io/32c3-slides/7130.html](https://lab.dsst.io/32c3-slides/7130.html)
* Python: List of most of dangerous APIs [https://docs.openstack.org/bandit/latest/blacklists/blacklist_calls.html](https://docs.openstack.org/bandit/latest/blacklists/blacklist_calls.html)
* [https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/](https://blog.trailofbits.com/2019/11/07/attacking-go-vr-ttps/) Go lang audit tips
* [https://vulncat.fortify.com/en/weakness](https://vulncat.fortify.com/en/weakness) ref. for many languages
* [https://rules.sonarsource.com/](https://rules.sonarsource.com/) pretty good and up to date ref for many languages.
* [https://securitylab.github.com/events/2020-02-14-offensivecon](https://securitylab.github.com/events/2020-02-14-offensivecon) **Great kick-start workshop for learning CodeQL**
* [https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html](https://help.semmle.com/codeql/codeql-for-vscode/procedures/setting-up.html) **CodeQL setup guide for VS Code.**

## Wireless comm

* Sniffing 4.9GHz public safety spectrum [https://github.com/Subterfuge-Framework/Subterfuge](https://github.com/Subterfuge-Framework/Subterfuge)
* SkyNet [http://static.usenix.org/events/woot11/tech/final_files/Reed.pdf](http://static.usenix.org/events/woot11/tech/final_files/Reed.pdf)
* [http://blog.opensecurityresearch.com/2012/06/getting-started-with-gnu-radio-and-rtl.html](http://blog.opensecurityresearch.com/2012/06/getting-started-with-gnu-radio-and-rtl.html)

## Kubernetes

* [https://www.inguardians.com/2018/12/12/attacking-and-defending-kubernetes-bust-a-kube-episode-1/](https://www.inguardians.com/2018/12/12/attacking-and-defending-kubernetes-bust-a-kube-episode-1/)
* [https://raesene.github.io/blog/2016/10/08/Kubernetes-From-Container-To-Cluster/](https://raesene.github.io/blog/2016/10/08/Kubernetes-From-Container-To-Cluster/)
* [https://www.youtube.com/watch?v=vTgQLzeBfRU](https://www.youtube.com/watch?v=vTgQLzeBfRU) Hacking and Hardening Kubernetes Clusters by Example
* [https://www.youtube.com/watch?time_continue=72&v=1k-GIDXgfLw](https://www.youtube.com/watch?time_continue=72&v=1k-GIDXgfLw) Good (security) intro into kubernetes
* [https://www.youtube.com/watch?v=n9ljS-TQRQE](https://www.youtube.com/watch?v=n9ljS-TQRQE) another useful basics intro
* [https://www.cisecurity.org/benchmark/kubernetes/](https://www.cisecurity.org/benchmark/kubernetes/) CIS Kubernetes Benchmark v1.4.0

# +Interesting tools:+

## OSINT

### Psssive:

* [https://dnsdumpster.com](https://dnsdumpster.com) Passive DNS recon
* [https://www.passivetotal.org](https://www.passivetotal.org) Passive multi-source threats and info gathering (requires subscription)
* [https://www.censys.io](https://www.censys.io) Internet scan (DNS,SSL,Web,Mail) results search
* [https://scans.io](https://scans.io) Regularly updated IPv4 space scan raw data
* [http://bgp.he.net/AS23148#_prefixes](http://bgp.he.net/AS23148#_prefixes) For discovering all IPs related to targets using BGP. Mix with google dorks.
* [https://whois.domaintools.com](https://whois.domaintools.com) Extensive reverse-dns lookup (not free for large results)
* [http://urlfind.org/](http://urlfind.org/) URL and cross-domain mapping
* [https://www.virustotal.com/en/search/](https://www.virustotal.com/en/search/) Searching domains,emails,IP,strings,...
* Maltego: Multi source/purpose OSINT tool (some modules are not passive!) [https://www.paterva.com/web6/products/maltego.php](https://www.paterva.com/web6/products/maltego.php)
* Harvester: Gather emails/vhosts/sub-domains using search engines [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)

### Active:

* Fierce: DNS brute-force tool [http://tools.kali.org/information-gathering/fierce](http://tools.kali.org/information-gathering/fierce)
* TXDNS: Fast DNS brute-force (win) [http://www.vulnerabilityassessment.co.uk/txdns.htm](http://www.vulnerabilityassessment.co.uk/txdns.htm)
* Large hostname dictionary [https://github.com/TheRook/subbrute/blob/master/names.txt](https://github.com/TheRook/subbrute/blob/master/names.txt)
* FOCA: Extensive passive & active OSINT and meta-data enumeration (win) [https://www.elevenpaths.com/labstools/foca/](https://www.elevenpaths.com/labstools/foca/)
* SpiderFoot: Python do-over of a great old tool, THE OSIG TOOL to use specially for larger targets and corps. [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
* [https://github.com/nahamsec/lazys3](https://github.com/nahamsec/lazys3) scan AWS instances for a domain

## Web-App assessment tools:

* _Burp-Suite_: Various automated/manual features. Automatic scanner in Pro [https://portswigger.net/burp/](https://portswigger.net/burp/)
* BurpSuite Plugin: AuthMatrix (for testing proper auth implemenations) [http://zuxsecurity.blogspot.de/2016/01/authmatrix-for-burp-suite.html](http://zuxsecurity.blogspot.de/2016/01/authmatrix-for-burp-suite.html)
* BurpSuite Plugin: StaticScan (offline JS audit) [https://github.com/tomsteele/burpstaticscan](https://github.com/tomsteele/burpstaticscan)
* BurpSuite Plugin: Blazer (AMF Testing) [https://github.com/ikkisoft/blazer](https://github.com/ikkisoft/blazer)
* Many other BurpSuite Plugins: [https://portswigger.net/bappstore/](https://portswigger.net/bappstore/)
* _SoapUI:_ Parsing and testing web services, mix with BurpSuite,bur also has some limited security tests (XSS/SQLi/XMLi) [https://www.soapui.org/downloads/soapui.html](https://www.soapui.org/downloads/soapui.html)
* _Arachni-Scanner:_ automated web scanner [http://www.arachni-scanner.com/](http://www.arachni-scanner.com/)
* _W3AF:_ Semi-automated web scanner (many useful plugins) [http://w3af.org/](http://w3af.org/)
* _Dir-Buster:_ Fast dir burute-force with extensive dic files [https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
* _IIS-ShortName-Scanner:_ Abuse IIS misconfig to grab dir/file 8.3 (also possible with Nmap NSE script) names [https://github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)
* _Nmap --script=http-_\* Many useful NSE scripts for web-apps and enumeration [https://nmap.org/nsedoc/index.html](https://nmap.org/nsedoc/index.html)
* _OWASP ZAP:_ Similar to Burp (win) [https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)
* _Fiddler:_ similar to burp and ZAP [http://www.telerik.com/fiddler](http://www.telerik.com/fiddler)
* _SQLmap:_ automated SQLi detect/exploit [http://sqlmap.org/](http://sqlmap.org/)
* _SQLninja:_ automated SQLi (useful plugins & scripts for win/ms-sql/OOB) [http://sqlninja.sourceforge.net/index.html](http://sqlninja.sourceforge.net/index.html)
* _DOMinatorPro:_ DOM based attacks tool [https://dominator.mindedsecurity.com/](https://dominator.mindedsecurity.com/)
* _Xcat:_ XPath injection tool [https://github.com/orf/xcat](https://github.com/orf/xcat)
* _deblaze:_ AMF endpoint enumeration and interaction [https://github.com/SpiderLabs/deblaze](https://github.com/SpiderLabs/deblaze)
* _blazentoo_ AMF attack tool for abusing proxy endpoints [https://github.com/GDSSecurity/blazentoo](https://github.com/GDSSecurity/blazentoo)
* _JMET_ Java serialization attacks payload generator [https://github.com/matthiaskaiser/jmet](https://github.com/matthiaskaiser/jmet)
* _Useful Firefox/Chrome plugins:_
* FireBug: Debugging web pages, scripts, cookies, etc [http://getfirebug.com/](http://getfirebug.com/)
* FlashBug: Firebug plugin for auditing flash apps, including decompile
* WebApplyzer: detecting web-app technology [https://wappalyzer.com/](https://wappalyzer.com/)
* PassiveRecon: detecting web-app technology [https://addons.mozilla.org/en-US/firefox/addon/passiverecon/](https://addons.mozilla.org/en-US/firefox/addon/passiverecon/)
* User-Agent Switcher: change broswer UA [http://chrispederick.com/work/user-agent-switcher/](http://chrispederick.com/work/user-agent-switcher/)
* FoxyProxy: quickly change to different proxy settings (or use proxy based on pattern matching) [https://getfoxyproxy.org/](https://getfoxyproxy.org/)
* Retire.js: auto detect outdated 3rd party JS libs included in the web-app [http://bekk.github.io/retire.js/](http://bekk.github.io/retire.js/)
* List of other interesting plugins [http://www.getmantra.com/tools.html](http://www.getmantra.com/tools.html)
* [https://github.com/welk1n/JNDI-Injection-Exploit](https://github.com/welk1n/JNDI-Injection-Exploit) JNDI-injection tool
* [https://github.com/lobuhi/byp4xx.git](https://github.com/lobuhi/byp4xx.git) 403 bypass checks
* [https://github.com/sting8k/BurpSuite_403Bypasser](https://github.com/sting8k/BurpSuite_403Bypasser) 403 bypass checks, Burp plugin

## SAP/ERP:

* ERPScan tools: multiple useful SAP audit tools (mix modules with Burp!) [https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/](https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/)
* Metasploit SAP modules:
* SAPyto: SAP pentest framework [https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/](https://erpscan.com/research/free-pentesting-tools-for-sap-and-oracle/)
* BizSploit: free/commercial SAP pentest framework [https://www.onapsis.com/research/free-solutions](https://www.onapsis.com/research/free-solutions)
* SAPPy [https://github.com/jacebrowning/sappy](https://github.com/jacebrowning/sappy)

## Database (Oracle,MySQL,MSSQL,...)

* Multiple Oracle audit and scan tools to brute/enum/exploit oracle [http://www.cqure.net/wp/tools/database/](http://www.cqure.net/wp/tools/database/)
* AppDetective Pro: Commercial (with trial) extensive vuln-assessment and audit for many DB platforms [https://www.trustwave.com/Products/Database-Security/AppDetectivePRO/](https://www.trustwave.com/Products/Database-Security/AppDetectivePRO/)
* McAfee DSS: commercial (with trial) database vuln-assessment and audit tool [http://www.mcafee.com/us/products/security-scanner-for-databases.aspx](http://www.mcafee.com/us/products/security-scanner-for-databases.aspx)
* Metasploit modules: many useful brute/enum/exploit modules
* Canvas modules: a number of useful enum/exploit modules
* Nmap NSE: many useful nmap scripts for recon/audit/enum
* MSSQL post-exploitation [http://mssqlpostexploit.codeplex.com/](http://mssqlpostexploit.codeplex.com/)

> 

## Code audit tools:

* [https://securitylab.github.com/tools/codeql](https://securitylab.github.com/tools/codeql) **must-learn** semantic code auditing tool for all (supported) languages.
* [https://www.jetbrains.com/idea/](https://www.jetbrains.com/idea/) IntelliJ IDEA Ultimate IDE: great search/back-trace/debugging features useful during audit
* [https://github.com/agelastic/intellij-code-audit/](https://github.com/agelastic/intellij-code-audit/) IntelliJ Java audit policies: extra audit policies for IDEA
* [http://rips-scanner.sourceforge.net](http://rips-scanner.sourceforge.net) RIPS (PHP): Obsolete but still useful static audit (new redesign will be out soon)
* [http://php-grinder.com/](http://php-grinder.com/)
* [http://www.devbug.co.uk/](http://www.devbug.co.uk/)
* [https://github.com/FloeDesignTechnologies/phpcs-security-audit](https://github.com/FloeDesignTechnologies/phpcs-security-audit) grep for interesting keywords
* [https://github.com/find-sec-bugs/find-sec-bugs](https://github.com/find-sec-bugs/find-sec-bugs) Find-Security-Bugs (Java)
* [https://github.com/tomsteele/burpstaticscan](https://github.com/tomsteele/burpstaticscan) Burp Static Scan: auditing JS using burpSuite static-scan engine
* [http://www.downloadcrew.com/article/26642-swfscan](http://www.downloadcrew.com/article/26642-swfscan) HP SWFscan: Automatic decompile and basic audit of flash (obsolete, but useful)
* [http://labs.adobe.com/technologies/swfinvestigator/](http://labs.adobe.com/technologies/swfinvestigator/) Adobe SWFinvestigator: Useful for static/dynamic audit of flash apps
* [https://github.com/nccgroup/VCG/tree/master/VisualCodeGrepper](https://github.com/nccgroup/VCG/tree/master/VisualCodeGrepper) Visual-Code-Grepp useful collection of patterns and keywords(win) C/C++, Java, C#, VB and PL/SQL
* [https://dominator.mindedsecurity.com/](https://dominator.mindedsecurity.com/) DOMinatorPro: DOM based attacks tool
* [http://www.computec.ch/projekte/codex/](http://www.computec.ch/projekte/codex/)
* [http://marketplace.eclipse.org/content/contrast-eclipse](http://marketplace.eclipse.org/content/contrast-eclipse) WASP Top 10 detection plugin for Eclipse
* [http://code-pulse.com/](http://code-pulse.com/) code coverage monitoring for blackbox app tests
* [http://jshint.com/](http://jshint.com/) JS static code analysis
* [https://pmd.github.io](https://pmd.github.io) classic static code analyzer supporting many langs.
* [https://jeremylong.github.io/DependencyCheck/index.html](https://jeremylong.github.io/DependencyCheck/index.html) Scans various source & config files and cross-check with CVE DB to report outdated libraries.
* [https://nodesecurity.io/opensource](https://nodesecurity.io/opensource) NSP scans Node.js applications for outdated modules.
* [http://retirejs.github.io/retire.js/](http://retirejs.github.io/retire.js/) Scans JS/Node codes and applications for outdated modules and libraries
* [https://github.com/dpnishant/raptor](https://github.com/dpnishant/raptor) web-based (web-serivce + UI) github centric source-vulnerability scanner
* [https://github.com/presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) Ruby on Rails static code scanner
* [https://github.com/rubysec/bundler-audit](https://github.com/rubysec/bundler-audit) Auditing Ruby 3rd party libs versions
* [https://github.com/rubygarage/inquisition](https://github.com/rubygarage/inquisition) Ruby auditing tools gem
* [https://github.com/thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner) Ruby applications security scanner
* [https://github.com/antitree/manitree](https://github.com/antitree/manitree) Android Apps manifest.xml audit
* [https://github.com/Microsoft/DevSkim/](https://github.com/Microsoft/DevSkim/) Visual-Stuudio/Code plugin with base rules for highlighting (C#, C++, JS, SQL, ...) issues.
* [https://www.nuget.org/packages/SafeNuGet/](https://www.nuget.org/packages/SafeNuGet/) Scans 3rd party libs used in .Net apps for known issues. Also bundles with VS.
* [https://www.viva64.com/en/pvs-studio/](https://www.viva64.com/en/pvs-studio/) Static code (security) analysis, also bundles with VS.
* [https://github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) Static code (security) analysis for Python. Extendable with plugins.
* [https://requires.io](https://requires.io) Automatic check of Python pip package versions against known vulns. Create a repo with required.pip list on github and point the site to it.
* [https://pyup.io/safety/](https://pyup.io/safety/) checks requirements.txt for outdated and vulnerable imports
* [https://github.com/fkie-cad/cwe_checker](https://github.com/fkie-cad/cwe_checker) ELF static analyser based on BAD (Intel/ARM/MIPS/PPC, +IDA/Ghidra
* [https://pyre-check.org/](https://pyre-check.org/) Python lib for taint analysis via sinks.
* [https://github.com/security-code-scan/security-code-scan](https://github.com/security-code-scan/security-code-scan) C# audit tool (like FindSecBugs for java).
* [https://gitlab.immunityinc.com/consultingresearch/code-graph-auditor-intellij-plugin](https://gitlab.immunityinc.com/consultingresearch/code-graph-auditor-intellij-plugin) Code-Graph-Auditor for IDEA (internal tool)
* [https://semgrep.dev/](https://semgrep.dev/) multi-language AST powered audit tool with easy to use rule syntax. (Good CodeQL alternative)
* [https://github.com/visma-prodsec/confused](https://github.com/visma-prodsec/confused) Dependency Confusion check (pypi,npm,php,mvn)
* [https://github.com/visma-prodsec/ConfusedDotnet](https://github.com/visma-prodsec/ConfusedDotnet) Dependency Confusion check for .Net nugets

## Android/iOS audit tools & checklists:

* [http://www.3u.com/](http://www.3u.com/) The iTunes (and more + tweak) alternative for iOS
* [https://github.com/iSECPartners/LibTech-Auditing-Cheatsheet](https://github.com/iSECPartners/LibTech-Auditing-Cheatsheet)
* [https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
* [https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) Detailed audit of APK files for config/security issues
* [https://github.com/AndroBugs/AndroBugs_Framework](https://github.com/AndroBugs/AndroBugs_Framework) quick static analysis of apk files
* [https://github.com/ashishb/android-security-awesome](https://github.com/ashishb/android-security-awesome) collection of android sec. related tools list
* [https://www.owasp.org/index.php/Android_Testing_Cheat_Sheet](https://www.owasp.org/index.php/Android_Testing_Cheat_Sheet)
* [https://www.ostorlab.co/](https://www.ostorlab.co/) Online app analysis sandbox & static analysis
* [http://sanddroid.xjtu.edu.cn/](http://sanddroid.xjtu.edu.cn/) Online app analysis sandbox & static analysis
* [https://github.com/sensepost/objection](https://github.com/sensepost/objection) Frida based framework for iOS/Android (+auto resign & deploy apps)
* [https://github.com/chaitin/passionfruit](https://github.com/chaitin/passionfruit) Frida based framework for iOS
* [https://github.com/ChiChou/Grapefruit](https://github.com/ChiChou/Grapefruit) Newer tool raised from Passionfruit, for iOS
* [https://github.com/nccgroup/house](https://github.com/nccgroup/house) Frida based framework for Android, similar to PassionFruit
* [https://github.com/linkedin/qark](https://github.com/linkedin/qark) Android app review kit
* [https://github.com/vtky/Swizzler2](https://github.com/vtky/Swizzler2) Frida based toolkit for testing iOS/Android apps and MDM solutions
* [https://github.com/JesusFreke/smali](https://github.com/JesusFreke/smali) Android DEX format (.smali files) \[dis\]assembler
* [https://github.com/AloneMonkey/frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) pull decrypted IPA from jailbroken iOS
* [https://github.com/ay-kay/cda](https://github.com/ay-kay/cda) cmd tool to search/list installed iOS apps and details
* [https://github.com/NitinJami/keychaineditor](https://github.com/NitinJami/keychaineditor) iOS keychain dump/edit on jailbroken devices
* [https://github.com/ptoomey3/Keychain-Dumper](https://github.com/ptoomey3/Keychain-Dumper) iOS keychain dumper
* [https://github.com/nowsecure/node-applesign](https://github.com/nowsecure/node-applesign) NodeJS tool for easy re-sign of iOS apps
* [https://github.com/dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida) Awesome Frida based tools/libs/resources
* [https://tinyhack.com/2018/02/05/pentesting-obfuscated-android-app/](https://tinyhack.com/2018/02/05/pentesting-obfuscated-android-app/) Deobfuscate Android apps
* [https://marketplace.visualstudio.com/items?itemName=codecolorist.vscode-frida](https://marketplace.visualstudio.com/items?itemName=codecolorist.vscode-frida) Frida plugin for VS-Code
* [https://github.com/skylot/jadx](https://github.com/skylot/jadx) Android (APK)/Java decompiler
* [https://github.com/oversecured/ovaa](https://github.com/oversecured/ovaa) Lots of vuln types examples in a mobile app
* [https://github.com/blacktop/ipsw](https://github.com/blacktop/ipsw) iOS/MacOS research Swiss army knife

## Frida Scripts

* [https://codeshare.frida.re/@mrmacete/objc-method-observer/](https://codeshare.frida.re/@mrmacete/objc-method-observer/) monitor class/method calls
* [https://github.com/noobpk/frida-ios-hook](https://github.com/noobpk/frida-ios-hook) hook methods

## Wireless/BlueTooth/RFID/etc.

* Live RFID hacking distro [http://www.openpcd.org/Live_RFID_Hacking_System](http://www.openpcd.org/Live_RFID_Hacking_System)
* automated WPS exploit script [https://github.com/derv82/wifite](https://github.com/derv82/wifite)
* [https://github.com/OpenSecurityResearch/hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe)
* [https://www.kismetwireless.net/kisbee/](https://www.kismetwireless.net/kisbee/) Zigbee open-source hardware
* [https://www.kismetwireless.net/android-pcap/](https://www.kismetwireless.net/android-pcap/) 802.11 capturing for andorid
* [https://github.com/SecUpwN/Android-IMSI-Catcher-Detector](https://github.com/SecUpwN/Android-IMSI-Catcher-Detector)
* [https://www.adafruit.com/product/1497](https://www.adafruit.com/product/1497)
* [http://www.p1sec.com/corp/research/tools/sctpscan/](http://www.p1sec.com/corp/research/tools/sctpscan/)
* [http://www.shellntel.com/blog/2015/9/23/assessing-enterprise-wireless-networks](http://www.shellntel.com/blog/2015/9/23/assessing-enterprise-wireless-networks) crEAP - Harvesting Users on Enterprise Wireless Networks
* [https://n0where.net/wps-attack-tool-penetrator-wps/](https://n0where.net/wps-attack-tool-penetrator-wps/)
* [https://github.com/conorpp/btproxy](https://github.com/conorpp/btproxy) Bluetooth MiTM proxy
* [https://github.com/omriiluz/NRF24-BTLE-Decoder](https://github.com/omriiluz/NRF24-BTLE-Decoder)
* [https://github.com/riverloopsec/killerbee](https://github.com/riverloopsec/killerbee) ZigBee attack framework
* [https://github.com/sophron/wifiphisher](https://github.com/sophron/wifiphisher) phishing against wifi clients
* [https://github.com/samyk/keysweeper](https://github.com/samyk/keysweeper) sniffing wireless keyboards
* [https://github.com/JiaoXianjun/LTE-Cell-Scanner](https://github.com/JiaoXianjun/LTE-Cell-Scanner)
* [https://github.com/sharebrained/portapack-hackrf](https://github.com/sharebrained/portapack-hackrf) HackRF LCD display
* [https://github.com/2b-as/xgoldmon](https://github.com/2b-as/xgoldmon) convert USB debug logsphones with XGold baseband processor back to the GSM/UMTS
* [http://www.silca.biz/en/products/key-replacement-business/residential-remotes/916270/remotes-air4.html](http://www.silca.biz/en/products/key-replacement-business/residential-remotes/916270/remotes-air4.html) Device to clone door remotes
* [http://www.rmxlabs.ru/products/keymaster_pro_4_rf/](http://www.rmxlabs.ru/products/keymaster_pro_4_rf/) device to clone LF (125KHz) RFID tags
* [http://www.fortresslock.co.uk/welcome/trade-area/smartcard-deluxe-2/](http://www.fortresslock.co.uk/welcome/trade-area/smartcard-deluxe-2/) similar to above, in EU market.
* [http://www.bishopfox.com/resources/tools/rfid-hacking/attack-tools/](http://www.bishopfox.com/resources/tools/rfid-hacking/attack-tools/) Longer range LF tag cloner (3 feet), easy to build.
* [http://www.d-logic.net/nfc-rfid-reader-sdk/products/nfc-usb-stick-dl533n](http://www.d-logic.net/nfc-rfid-reader-sdk/products/nfc-usb-stick-dl533n) NFC/RFID (HF) USB dungle + Android app

## Hardware hacking

* BusPirate [http://dangerousprototypes.com/docs/Bus_Pirate](http://dangerousprototypes.com/docs/Bus_Pirate)
* JTAGulator [http://www.grandideastudio.com/portfolio/jtagulator/](http://www.grandideastudio.com/portfolio/jtagulator/)
* BinWalk [https://github.com/devttys0/binwalk](https://github.com/devttys0/binwalk)
* Firmware-Mod-Kit [https://code.google.com/archive/p/firmware-mod-kit/](https://code.google.com/archive/p/firmware-mod-kit/)
* [http://firmware.re/](http://firmware.re/)
* [https://github.com/adamcaudill/Psychson](https://github.com/adamcaudill/Psychson) BadUSB poc
* [https://www.pjrc.com/teensy/](https://www.pjrc.com/teensy/)
* [http://rada.re/r/](http://rada.re/r/) Reversing MIPS
* [https://www.yoctoproject.org/tools-resources](https://www.yoctoproject.org/tools-resources) MIPS/ARM emulator
* [http://int3.cc/products/facedancer21](http://int3.cc/products/facedancer21)
* [http://int3.cc/products/osprey](http://int3.cc/products/osprey)

## Kubernetes

* [https://github.com/cyberark/KubiScan](https://github.com/cyberark/KubiScan) Tools for auditing master node configs
* [https://github.com/aquasecurity/kube-hunter](https://github.com/aquasecurity/kube-hunter) Tools for remote test of clusters for common issues
* [https://github.com/aquasecurity/kube-bench](https://github.com/aquasecurity/kube-bench) Tool for local audit of pod/master nodes against CIS benchamrk
* [https://github.com/nccgroup/kube-auto-analyzer](https://github.com/nccgroup/kube-auto-analyzer) Tool for local audit of pod/master nodes, can also deploy agent

## VPN

* [https://github.com/royhills/ike-scan](https://github.com/royhills/ike-scan)
* [https://github.com/SpiderLabs/ikeforce](https://github.com/SpiderLabs/ikeforce)
* [https://github.com/interspective/bike-scan](https://github.com/interspective/bike-scan)
* [https://github.com/historypeats/psikeo](https://github.com/historypeats/psikeo)

## VoIP

* [https://github.com/fozavci/viproy-voipkit](https://github.com/fozavci/viproy-voipkit)
* [http://www.voipsa.org/Resources/tools.php](http://www.voipsa.org/Resources/tools.php) Directory of good tools for VoIP hacking

## Chrome Extensions

* Basics [https://developer.chrome.com/extensions/overview#arch](https://developer.chrome.com/extensions/overview#arch)
* [https://www.chromium.org/Home/chromium-security/education/security-tips-for-crx-and-apps](https://www.chromium.org/Home/chromium-security/education/security-tips-for-crx-and-apps)
* [http://resources.infosecinstitute.com/owned-by-chrome-extensions/#gref](http://resources.infosecinstitute.com/owned-by-chrome-extensions/#gref)
* [http://kyleosborn.com/bh2012/advanced-chrome-extension-exploitation-WHITEPAPER.pdf](http://kyleosborn.com/bh2012/advanced-chrome-extension-exploitation-WHITEPAPER.pdf)
* Insecure Messaging issues like [https://bugs.chromium.org/p/project-zero/issues/detail?id=1527&desc=2#maincol](https://bugs.chromium.org/p/project-zero/issues/detail?id=1527&desc=2#maincol)
* [https://github.com/koto/xsschef](https://github.com/koto/xsschef)
* Use Node/JS module scanners like NSP and SNYK ([https://snyk.io/](https://snyk.io/)) against source

## AWS, Azur, etc.

* [https://github.com/SecurityFTW/cs-suite](https://github.com/SecurityFTW/cs-suite) Automated auditing of AWS/GCP/Azure
* [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) Multi-cloud audit tool
* [https://github.com/cyberark/SkyArk](https://github.com/cyberark/SkyArk) Identify & audit privileged entities in Azure and AWS
* [https://github.com/nccgroup/Scout2](https://github.com/nccgroup/Scout2) AWS Audit tool by NCC (recommended)
* [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner) Finds & dumps open S3 buckets
* [https://github.com/jordanpotti/AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
* [https://github.com/dagrz/aws_pwn](https://github.com/dagrz/aws_pwn) AWS testing scripts
* [https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation) AWS priv-escalation (text)
* [https://github.com/DenizParlak/Zeus](https://github.com/DenizParlak/Zeus) AWS auditing & hardening tool
* [https://github.com/FSecureLABS/awspx](https://github.com/FSecureLABS/awspx) Graph-based visualising effective access & resource relationships in AWS
* [https://github.com/Ucnt/aws-s3-downloader](https://github.com/Ucnt/aws-s3-downloader) Downloading S3 buckets
* Check Burp-Suite store for AWS/Azure related extensions. Good stuff there too.

## Linux LPE/Audit

* [https://gtfobins.github.io/](https://gtfobins.github.io/)
* [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) Bash script finding common LPE vectors
* [https://github.com/sleventyeleven/linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) Python script finding common LPE vectors
* [https://github.com/CISOfy/lynis](https://github.com/CISOfy/lynis) \*nix local auidit/test/hardening tool in Bash.

## Win LPE/Audit

* [https://www.kitploit.com/2020/10/patchchecker-web-based-check-for.html](https://www.kitploit.com/2020/10/patchchecker-web-based-check-for.html) quick check for missing patches for LPE
* [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Misc

* Smartphone pentest framework [http://www.bulbsecurity.com/smartphone-pentest-framework/](http://www.bulbsecurity.com/smartphone-pentest-framework/)
* OCSP Client Tool [http://www.ascertia.com/products/ocsp-client-tool](http://www.ascertia.com/products/ocsp-client-tool)
* JSmartCardExplorer [https://www.primianotucci.com/os/smartcard-explorer](https://www.primianotucci.com/os/smartcard-explorer)
* Mimikatz [http://blog.gentilkiwi.com/mimikatz](http://blog.gentilkiwi.com/mimikatz)
* Bettercap sniffer [https://www.bettercap.org/](https://www.bettercap.org/)
* Subterfuge MiTM framework [https://github.com/Subterfuge-Framework/Subterfuge](https://github.com/Subterfuge-Framework/Subterfuge)
* .Net Reflector: decompiler [http://www.red-gate.com/products/dotnet-development/reflector/](http://www.red-gate.com/products/dotnet-development/reflector/)
* Zanti mobile pentest framework [https://www.zimperium.com/zanti-mobile-penetration-testing](https://www.zimperium.com/zanti-mobile-penetration-testing)
* [https://www.christophertruncer.com/veil-a-payload-generator-to-bypass-antivirus/](https://www.christophertruncer.com/veil-a-payload-generator-to-bypass-antivirus/)
* Malloy: TCP/UDP proxy [http://intrepidusgroup.com/insight/mallory/](http://intrepidusgroup.com/insight/mallory/)
* GNU tools for win32 [https://github.com/bmatzelle/gow/wiki](https://github.com/bmatzelle/gow/wiki)
* Window console emulator [https://conemu.github.io/](https://conemu.github.io/)
* DVBsnoop [http://dvbsnoop.sourceforge.net/](http://dvbsnoop.sourceforge.net/)
* Introspy-IOS: IOS app profiling tool [https://github.com/iSECPartners/Introspy-iOS](https://github.com/iSECPartners/Introspy-iOS)
* [http://www.frida.re/](http://www.frida.re/)
* Decompile and view RPC info [http://rpcview.org/](http://rpcview.org/)
* [https://www.bro.org/](https://www.bro.org/) network monitoring and traffic analysis
* [https://github.com/mikispag/rosettaflash](https://github.com/mikispag/rosettaflash) Rosetta Flash (CVE-2014-4671)
* [http://mitmproxy.org/](http://mitmproxy.org/) MiTM proxy tool
* Pytbull: IDS/IPS testing tool [http://pytbull.sourceforge.net/](http://pytbull.sourceforge.net/)
* Fakenet: dynamic malware behaviour analysis [http://pytbull.sourceforge.net/](http://pytbull.sourceforge.net/)
* PowerSploit: Powershell based exploit framework [https://github.com/mattifestation/PowerSploit](https://github.com/mattifestation/PowerSploit)
* [http://x64dbg.com/#start](http://x64dbg.com/#start)
* [https://thesprawl.org/projects/ida-sploiter/](https://thesprawl.org/projects/ida-sploiter/)
* [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) fast nmap alternative
* [https://github.com/coresecurity/impacket](https://github.com/coresecurity/impacket) python lib for packet generation of multiple protocols
* [http://pentestmonkey.net/tools/windows-privesc-check](http://pentestmonkey.net/tools/windows-privesc-check) finds weak permissions on win for priv-escalation
* [https://github.com/iSECPartners/ios-ssl-kill-switch](https://github.com/iSECPartners/ios-ssl-kill-switch) disable SSL cert validation in IOS
* [https://retdec.com/](https://retdec.com/) online binary decompiler (Intel x86, ARM, ARM+Thumb, MIPS, PIC32, PowerPC)
* [http://goaccess.io/screenshots](http://goaccess.io/screenshots) Apache log analysis and monitor
* [https://www.onlinedisassembler.com/odaweb/](https://www.onlinedisassembler.com/odaweb/)
* [http://www.reconstructer.org/](http://www.reconstructer.org/) Office doc malware scanner
* [https://getgophish.com/](https://getgophish.com/) phishing framework
* [http://salmanarif.bitbucket.org/visual/index.html](http://salmanarif.bitbucket.org/visual/index.html) ARM visual emulator
* [https://github.com/giMini/PowerMemory/tree/master/RWMC](https://github.com/giMini/PowerMemory/tree/master/RWMC) Powershell - Reveal Windows Memory Credentials
* [https://launchpad.net/\~pi-rho/+archive/ubuntu/security](https://launchpad.net/\~pi-rho/+archive/ubuntu/security) debian PPA for common sec. tools
* [https://zmap.io/](https://zmap.io/) fast port scanner for scanning entire internet
* [http://www.computec.ch/projekte/vulscan/?s=download](http://www.computec.ch/projekte/vulscan/?s=download) Vuln-scanner using NSE for Nmap (cross checking banners with CVEs)
* [https://code.google.com/archive/p/smtp-security-scanner/](https://code.google.com/archive/p/smtp-security-scanner/)
* [https://github.com/proteansec/fuzzyftp](https://github.com/proteansec/fuzzyftp) simple FTP fuzzer
* [http://www.xplico.org/](http://www.xplico.org/) Network traffic forensics tool
* [https://emcinformation.com/283102/REG/.ashx?reg_src=web](https://emcinformation.com/283102/REG/.ashx?reg_src=web) NetWitness Investigator: powerful network traffic analysis tool
* [https://www.bsk-consulting.de/apt-scanner-thor/](https://www.bsk-consulting.de/apt-scanner-thor/) interesting anomaly based malware detection
* [https://github.com/lanjelot/patator](https://github.com/lanjelot/patator) Python multi-protocol bruteforce script (using with Innuendo?)
* [https://github.com/nccgroup/BinProxy](https://github.com/nccgroup/BinProxy) Proxy tool for (binary) TCP connections. Supports SSL/TLS.

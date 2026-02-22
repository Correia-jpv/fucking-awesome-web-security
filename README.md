> [!IMPORTANT]  
> My Web Pentest Training is accepted by 🌎 [Black Hat 2025](www.blackhat.com/us-25/training/schedule/index.html#web-hacking-from--to--44516) 🎉🎉🎉 Please come and join the course with me 🤓
>
> To celebrate this unforgettable moment (and sorry for not updating the repo since a while), I'll do a complete revamp of all the contents of this long-lasting repository in the coming weeks to catch up with the knowledge and tricks that have happened over these years.

# Awesome Web Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
 🌎 [<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](www.w3.org/TR/html5/)

> 🐶 Curated list of Web Security materials and resources.

Needless to say, most websites suffer from various types of bugs which may eventually lead to vulnerabilities. Why would this happen so often? There can be many factors involved including misconfiguration, shortage of engineers' security skills, etc. To combat this, here is a curated list of Web Security materials and resources for learning cutting edge penetration techniques, and I highly encourage you to read this article  🌎 [So you want to be a web security researcher?](portswigger.net/blog/so-you-want-to-be-a-web-security-researcher)" first.

*Please read the [contribution guidelines](CONTRIBUTING.md) before contributing.*

---

<p align="center"><b>🌈 Want to strengthen your penetration skills?</b><br>I would recommend playing some <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">awesome-ctf</a>s.</p>

---

If you enjoy this awesome list and would like to support it, check out my 🌎 [Patreon](www.patreon.com/boik) page :)<br>Also, don't forget to check out my [repos](https://github.com/qazbnm456) 🐾 or say *hi* on my 🌎 [Twitter](twitter.com/qazbnm456)!

## Contents

- [Digests](#digests)
- [Forums](#forums)
- [Introduction](#intro)
  - [XSS](#xss---cross-site-scripting)
  - [Prototype Pollution](#prototype-pollution)
  - [CSV Injection](#csv-injection)
  - [SQL Injection](#sql-injection)
  - [Command Injection](#command-injection)
  - [ORM Injection](#orm-injection)
  - [FTP Injection](#ftp-injection)
  - [XXE](#xxe---xml-external-entity)
  - [CSRF](#csrf---cross-site-request-forgery)
  - [Clickjacking](#clickjacking)
  - [SSRF](#ssrf---server-side-request-forgery)
  - [Web Cache Poisoning](#web-cache-poisoning)
  - [Relative Path Overwrite](#relative-path-overwrite)
  - [Open Redirect](#open-redirect)
  - [SAML](#saml)
  - [Upload](#upload)
  - [Rails](#rails)
  - [AngularJS](#angularjs)
  - [ReactJS](#reactjs)
  - [SSL/TLS](#ssltls)
  - [Webmail](#webmail)
  - [NFS](#nfs)
  - [AWS](#aws)
  - [Azure](#azure)
  - [Fingerprint](#fingerprint)
  - [Sub Domain Enumeration](#sub-domain-enumeration)
  - [Crypto](#crypto)
  - [Web Shell](#web-shell)
  - [OSINT](#osint)
  - [DNS Rebinding](#dns-rebinding)
  - [Deserialization](#deserialization)
  - [OAuth](#oauth)
  - [JWT](#jwt)
- [Evasions](#evasions)
  - [XXE](#evasions-xxe)
  - [CSP](#evasions-csp)
  - [WAF](#evasions-waf)
  - [JSMVC](#evasions-jsmvc)
  - [Authentication](#evasions-authentication)
- [Tricks](#tricks)
  - [CSRF](#tricks-csrf)
  - [Clickjacking](#tricks-clickjacking)
  - [Remote Code Execution](#tricks-rce)
  - [XSS](#tricks-xss)
  - [SQL Injection](#tricks-sql-injection)
  - [NoSQL Injection](#tricks-nosql-injection)
  - [FTP Injection](#tricks-ftp-injection)
  - [XXE](#tricks-xxe)
  - [SSRF](#tricks-ssrf)
  - [Web Cache Poisoning](#tricks-web-cache-poisoning)
  - [Header Injection](#tricks-header-injection)
  - [URL](#tricks-url)
  - [Deserialization](#tricks-deserialization)
  - [OAuth](#tricks-oauth)
  - [Others](#tricks-others)
- [Browser Exploitation](#browser-exploitation)
- [PoCs](#pocs)
  - [Database](#pocs-database)
- [Cheetsheets](#cheetsheets)
- [Tools](#tools)
  - [Auditing](#tools-auditing)
  - [Command Injection](#tools-command-injection)
  - [Reconnaissance](#tools-reconnaissance)
    - [OSINT](#tools-osint)
    - [Sub Domain Enumeration](#tools-sub-domain-enumeration)
  - [Code Generating](#tools-code-generating)
  - [Fuzzing](#tools-fuzzing)
  - [Scanning](#tools-scanning)
  - [Penetration Testing](#tools-penetration-testing)
  - [Leaking](#tools-leaking)
  - [Offensive](#tools-offensive)
    - [XSS](#tools-xss)
    - [SQL Injection](#tools-sql-injection)
    - [Template Injection](#tools-template-injection)
    - [XXE](#tools-xxe)
    - [CSRF](#tools-csrf)
    - [SSRF](#tools-ssrf)
  - [Detecting](#tools-detecting)
  - [Preventing](#tools-preventing)
  - [Proxy](#tools-proxy)
  - [Webshell](#tools-webshell)
  - [Disassembler](#tools-disassembler)
  - [Decompiler](#tools-decompiler)
  - [DNS Rebinding](#tools-dns-rebinding)
  - [Others](#tools-others)
- [Social Engineering Database](#social-engineering-database)
- [Blogs](#blogs)
- [Twitter Users](#twitter-users)
- [Practices](#practices)
  - [Application](#practices-application)
  - [AWS](#practices-aws)
  - [XSS](#practices-xss)
  - [ModSecurity / OWASP ModSecurity Core Rule Set](#practices-modsecurity)
- [Community](#community)
- [Miscellaneous](#miscellaneous)

## Digests

- 🌎 [Hacker101](www.hacker101.com/) - Written by 🌎 [hackerone](www.hackerone.com/start-hacking).
- 🌎 [The Daily Swig - Web security digest](portswigger.net/daily-swig) - Written by 🌎 [PortSwigger](portswigger.net/).
- 🌎 [Web Application Security Zone by Netsparker](www.netsparker.com/blog/web-security/) - Written by 🌎 [Netsparker](www.netsparker.com/).
- 🌎 [Infosec Newbie](www.sneakymonkey.net/2017/04/23/infosec-newbie/) - Written by 🌎 [Mark Robinson](www.sneakymonkey.net/).
- 🌎 [The Magic of Learning](bitvijays.github.io/) - Written by 🌎 [@bitvijays](bitvijays.github.io/aboutme.html).
- 🌎 [CTF Field Guide](trailofbits.github.io/ctf/) - Written by 🌎 [Trail of Bits](www.trailofbits.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- 🌎 [tl;dr sec](tldrsec.com/) - Weekly summary of top security tools, blog posts, and security research.

## Forums

- [Phrack Magazine](http://www.phrack.org/) - Ezine written by and for hackers.
- 🌎 [The Hacker News](thehackernews.com/) - Security in a serious way.
- 🌎 [Security Weekly](securityweekly.com/) - The security podcast network.
- [The Register](http://www.theregister.co.uk/) - Biting the hand that feeds IT.
- 🌎 [Dark Reading](www.darkreading.com/Default.asp) - Connecting The Information Security Community.
- [HackDig](http://en.hackdig.com/) - Dig high-quality web security articles for hacker.

<a name="intro"></a>
## Introduction

<a name="xss"></a>
### XSS - Cross-Site Scripting

- 🌎 [Cross-Site Scripting – Application Security – Google](www.google.com/intl/sw/about/appsecurity/learning/xss/) - Written by 🌎 [Google](www.google.com/).
- <b><code>&nbsp;&nbsp;3003⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;418🍴</code></b> [H5SC](https://github.com/cure53/H5SC)) - Written by [@cure53](https://github.com/cure53).
- <b><code>&nbsp;&nbsp;5058⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;777🍴</code></b> [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)) - Written by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;57⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;136🍴</code></b> [XSS.png](https://github.com/LucaBongiorni/XSS.png)) - Written by @jackmasa.
- 🌎 [C.XSS Guide](excess-xss.com/) - Written by [@JakobKallin](https://github.com/JakobKallin) and 🌎 [Irene Lobo Valbuena](www.linkedin.com/in/irenelobovalbuena/).
- [THE BIG BAD WOLF - XSS AND MAINTAINING ACCESS](http://www.paulosyibelo.com/2018/06/the-big-bad-wolf-xss-and-maintaining.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="prototype-pollution"></a>
### Prototype Pollution

- <b><code>&nbsp;&nbsp;&nbsp;535⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88🍴</code></b> [Prototype pollution attack in NodeJS application](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)) - Written by [@HoLyVieR](https://github.com/HoLyVieR).
- 🌎 [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)](research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/) - Written by 🌎 [@securitymb](twitter.com/securitymb).
- 🌎 [Real-world JS - 1](blog.p6.is/Real-World-JS-1/) - Written by 🌎 [@po6ix](twitter.com/po6ix).

<a name="csv-injection"></a>
### CSV Injection

- 🌎 [CSV Injection -> Meterpreter on Pornhub](news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - Written by 🌎 [Andy](blog.zsec.uk/).
- [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html) - Written by [George Mauer](http://georgemauer.net/).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - CSV Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="sql-injection"></a>
### SQL Injection

- 🌎 [SQL Injection Cheat Sheet](www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - Written by 🌎 [@netsparker](twitter.com/netsparker).
- 🌎 [SQL Injection Wiki](sqlwiki.netspi.com/) - Written by 🌎 [NETSPI](www.netspi.com/).
- 🌎 [SQL Injection Pocket Reference](websec.ca/kb/sql_injection) - Written by 🌎 [@LightOS](twitter.com/LightOS).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="command-injection"></a>
### Command Injection

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Potential command injection in resolv.rb](https://github.com/ruby/ruby/pull/1777)) - Written by [@drigg3r](https://github.com/drigg3r).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="orm-injection"></a>
### ORM Injection

- [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by 🌎 [@h3xstream](twitter.com/h3xstream/).
- 🌎 [HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injection ?)](www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - Written by 🌎 [@_m0bius](twitter.com/_m0bius).
- 🌎 [ORM2Pwn: Exploiting injections in Hibernate ORM](www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - Written by 🌎 [Mikhail Egorov](0ang3el.blogspot.tw/).
- 🌎 [ORM Injection](www.slideshare.net/simone.onofri/orm-injection) - Written by 🌎 [Simone Onofri](onofri.org/).

<a name="ftp-injection"></a>
### FTP Injection

- [Advisory: Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by 🌎 [Timothy Morgan](plus.google.com/105917618099766831589).
- 🌎 [SMTP over XXE − how to send emails using Java's XML parser](shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - Written by 🌎 [Alexander Klink](shiftordie.de/).

<a name="xxe"></a>
### XXE - XML eXternal Entity

- 🌎 [XXE](phonexicum.github.io/infosec/xxe.html) - Written by 🌎 [@phonexicum](twitter.com/phonexicum).
- 🌎 [XML external entity (XXE) injection](portswigger.net/web-security/xxe) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [XML Schema, DTD, and Entity Attacks](www.vsecurity.com/download/publications/XMLDTDEntityAttacks.pdf) - Written by 🌎 [Timothy D. Morgan](twitter.com/ecbftw) and Omar Al Ibrahim.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/xxe-injection-payload-list](https://github.com/payloadbox/xxe-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox)
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)) - Written by various contributors.

<a name="csrf"></a>
### CSRF - Cross-Site Request Forgery

- 🌎 [Wiping Out CSRF](medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - Written by 🌎 [@jrozner](medium.com/@jrozner).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - CSRF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="clickjacking"></a>
### Clickjacking

- 🌎 [Clickjacking](www.imperva.com/learn/application-security/clickjacking/) - Written by 🌎 [Imperva](www.imperva.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;85⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [X-Frame-Options: All about Clickjacking?](https://github.com/cure53/Publications/blob/master/xfo-clickjacking.pdf?raw=true)) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="ssrf"></a>
### SSRF - Server-Side Request Forgery

- 🌎 [SSRF bible. Cheatsheet](docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by 🌎 [Wallarm](wallarm.com/).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - Server-Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="web-cache-poisoning"></a>
### Web Cache Poisoning

- 🌎 [Practical Web Cache Poisoning](portswigger.net/blog/practical-web-cache-poisoning) - Written by 🌎 [@albinowax](twitter.com/albinowax).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - Web Cache Deception](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="relative-path-overwrite"></a>
### Relative Path Overwrite

- 🌎 [Large-scale analysis of style injection by relative path overwrite](blog.acolyer.org/2018/05/28/large-scale-analysis-of-style-injection-by-relative-path-overwrite/) - Written by 🌎 [The Morning Paper](blog.acolyer.org/).
- 🌎 [MBSD Technical Whitepaper - A few RPO exploitation techniques](www.mbsd.jp/Whitepaper/rpo.pdf) - Written by 🌎 [Mitsui Bussan Secure Directions, Inc.](www.mbsd.jp/).

<a name="open-redirect"></a>
### Open Redirect

- 🌎 [Open Redirect Vulnerability](s0cket7.com/open-redirect-vulnerability/) - Written by 🌎 [s0cket7](s0cket7.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/open-redirect-payload-list](https://github.com/payloadbox/open-redirect-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="saml"></a>
### Security Assertion Markup Language (SAML)

- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part I](epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part II](epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part III](epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - SAML Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="upload"></a>
### Upload

- 🌎 [File Upload Restrictions Bypass](www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf) - Written by 🌎 [Haboob Team](www.exploit-db.com/author/?a=9381).
- <b><code>&nbsp;75400⭐</code></b> <b><code>&nbsp;16664🍴</code></b> [PayloadsAllTheThings - Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="rails"></a>
### Rails

- 🌎 [Rails Security - First part](hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).
- <b><code>&nbsp;&nbsp;1817⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;146🍴</code></b> [Zen Rails Security Checklist](https://github.com/brunofacca/zen-rails-security-checklist)) - Written by [@brunofacca](https://github.com/brunofacca).
- 🌎 [Rails SQL Injection](rails-sqli.org) - Written by [@presidentbeef](https://github.com/presidentbeef).
- [Official Rails Security Guide](http://guides.rubyonrails.org/security.html) - Written by 🌎 [Rails team](rubyonrails.org/).

<a name="angularjs"></a>
### AngularJS

- [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by 🌎 [Gareth Heyes](www.blogger.com/profile/10856178524811553475).
- [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by 🌎 [@garethheyes](twitter.com/garethheyes)

<a name="reactjs"></a>
### ReactJS

- [XSS via a spoofed React element](http://danlec.com/blog/xss-via-a-spoofed-react-element) - Written by [Daniel LeCheminant](http://danlec.com/).

<a name="ssl-tls"></a>
### SSL/TLS

- 🌎 [SSL & TLS Penetration Testing](www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by 🌎 [APTIVE](www.aptive.co.uk/).
- <b><code>&nbsp;&nbsp;&nbsp;615⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;128🍴</code></b> [Practical introduction to SSL/TLS](https://github.com/Hakky54/mutual-tls-ssl)) - Written by [@Hakky54](https://github.com/Hakky54).

<a name="webmail"></a>
### Webmail

- 🌎 [Why mail() is dangerous in PHP](blog.ripstech.com/2017/why-mail-is-dangerous-in-php/) - Written by 🌎 [Robin Peraglie](www.ripstech.com/).

<a name="nfs"></a>
### NFS

- 🌎 [NFS | PENETRATION TESTING ACADEMY](pentestacademy.wordpress.com/2017/09/20/nfs/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=b34422ce15164e99a193fea0ccc7a02f&uid=1959680352&nid=244+289476616) - Written by 🌎 [PENETRATION ACADEMY](pentestacademy.wordpress.com/).

<a name="aws"></a>
### AWS

- 🌎 [PENETRATION TESTING AWS STORAGE: KICKING THE S3 BUCKET](rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Written by Dwight Hohnstein from 🌎 [Rhino Security Labs](rhinosecuritylabs.com/).
- 🌎 [AWS PENETRATION TESTING PART 1. S3 BUCKETS](www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/) - Written by 🌎 [VirtueSecurity](www.virtuesecurity.com/).
- 🌎 [AWS PENETRATION TESTING PART 2. S3, IAM, EC2](www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/) - Written by 🌎 [VirtueSecurity](www.virtuesecurity.com/).
- 🌎 [Misadventures in AWS](labs.f-secure.com/blog/misadventures-in-aws) - Written by Christian Demko

<a name="azure"></a>
### Azure

- 🌎 [Common Azure Security Vulnerabilities and Misconfigurations](rhinosecuritylabs.com/cloud-security/common-azure-security-vulnerabilities/) - Written by 🌎 [@rhinobenjamin](twitter.com/rhinobenjamin).
- 🌎 [Cloud Security Risks (Part 1): Azure CSV Injection Vulnerability](rhinosecuritylabs.com/azure/cloud-security-risks-part-1-azure-csv-injection-vulnerability/) - Written by 🌎 [@spengietz](twitter.com/spengietz).

<a name="fingerprint"></a>
### Fingerprint

<a name="sub-domain-enumeration"></a>
### Sub Domain Enumeration

- 🌎 [A penetration tester’s guide to sub-domain enumeration](blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6) - Written by 🌎 [Bharath](blog.appsecco.com/@yamakira_).
- 🌎 [The Art of Subdomain Enumeration](blog.sweepatic.com/art-of-subdomain-enumeration/) - Written by 🌎 [Patrik Hudak](blog.sweepatic.com/author/patrik/).

<a name="crypto"></a>
### Crypto

- 🌎 [Applied Crypto Hardening](bettercrypto.org/) - Written by 🌎 [The bettercrypto.org Team](bettercrypto.org/).
- 🌎 [What is a Side-Channel Attack ?](www.csoonline.com/article/3388647/what-is-a-side-channel-attack-how-these-end-runs-around-encryption-put-everyone-at-risk.html) - Written by 🌎 [J.M Porup](www.csoonline.com/author/J.M.-Porup/).

<a name="web-shell"></a>
### Web Shell

- 🌎 [Hunting for Web Shells](www.tenable.com/blog/hunting-for-web-shells) - Written by 🌎 [Jacob Baines](www.tenable.com/profile/jacob-baines).
- 🌎 [Hacking with JSP Shells](blog.netspi.com/hacking-with-jsp-shells/) - Written by 🌎 [@_nullbind](twitter.com/_nullbind).

<a name="osint"></a>
### OSINT

- 🌎 [Hacking Cryptocurrency Miners with OSINT Techniques](medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by 🌎 [@s3yfullah](medium.com/@s3yfullah).
- 🌎 [OSINT x UCCU Workshop on Open Source Intelligence](www.slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence) - Written by 🌎 [Philippe Lin](www.slideshare.net/miaoski).
- 🌎 [102 Deep Dive in the Dark Web OSINT Style Kirby Plessas](www.youtube.com/watch?v=fzd3zkAI_o4) - Presented by 🌎 [@kirbstr](twitter.com/kirbstr).
- 🌎 [The most complete guide to finding anyone’s email](www.blurbiz.io/blog/the-most-complete-guide-to-finding-anyones-email) - Written by 🌎 [Timur Daudpota](www.blurbiz.io/).

<a name="dns-rebinding"></a>
### DNS Rebinding

- 🌎 [Attacking Private Networks from the Internet with DNS Rebinding](medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325) - Written by 🌎 [@brannondorsey](medium.com/@brannondorsey)
- 🌎 [Hacking home routers from the Internet](medium.com/@radekk/hackers-can-get-access-to-your-home-router-1ddadd12a7a7) - Written by 🌎 [@radekk](medium.com/@radekk)

<a name="deserialization"></a>
### Deserialization

- 🌎 [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - Written by 🌎 [@breenmachine](twitter.com/breenmachine).
- 🌎 [Attacking .NET deserialization](www.youtube.com/watch?v=eDfGpu3iE4Q) - Written by 🌎 [@pwntester](twitter.com/pwntester).
- 🌎 [.NET Roulette: Exploiting Insecure Deserialization in Telerik UI](www.youtube.com/watch?v=--6PiuvBGAU) - Written by 🌎 [@noperator](twitter.com/noperator).
- 🌎 [How to exploit the DotNetNuke Cookie Deserialization](pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/) - Written by 🌎 [CRISTIAN CORNEA](pentest-tools.com/blog/author/pentest-cristian/).
- 🌎 [HOW TO EXPLOIT LIFERAY CVE-2020-7961 : QUICK JOURNEY TO POC](www.synacktiv.com/en/publications/how-to-exploit-liferay-cve-2020-7961-quick-journey-to-poc.html) - Written by 🌎 [@synacktiv](twitter.com/synacktiv).

<a name="oauth"></a>
### OAuth

- 🌎 [Introduction to OAuth 2.0 and OpenID Connect](pragmaticwebsecurity.com/courses/introduction-oauth-oidc.html) - Written by 🌎 [@PhilippeDeRyck](twitter.com/PhilippeDeRyck).
- 🌎 [What is going on with OAuth 2.0? And why you should not use it for authentication.](medium.com/securing/what-is-going-on-with-oauth-2-0-and-why-you-should-not-use-it-for-authentication-5f47597b2611) - Written by 🌎 [@damianrusinek](medium.com/@damianrusinek).

<a name="jwt"></a>
### JWT

- 🌎 [Hardcoded secrets, unverified tokens, and other common JWT mistakes](r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/) - Written by 🌎 [@ermil0v](twitter.com/ermil0v).

## Evasions

<a name="evasions-xxe"></a>
### XXE

- 🌎 [Bypass Fix of OOB XXE Using Different encoding](twitter.com/SpiderSec/status/1191375472690528256) - Written by 🌎 [@SpiderSec](twitter.com/SpiderSec).

<a name="evasions-csp"></a>
### CSP

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Any protection against dynamic module import?](https://github.com/w3c/webappsec-csp/issues/243)) - Written by 🌎 [@shhnjk](twitter.com/@shhnjk).
- 🌎 [CSP: bypassing form-action with reflected XSS](labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - Written by 🌎 [Detectify Labs](labs.detectify.com/).
- [TWITTER XSS + CSP BYPASS](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).
- 🌎 [Neatly bypassing CSP](lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa) - Written by 🌎 [Wallarm](wallarm.com/).
- 🌎 [Evading CSP with DOM-based dangling markup](portswigger.net/blog/evading-csp-with-dom-based-dangling-markup) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [GitHub's CSP journey](githubengineering.com/githubs-csp-journey/) - Written by [@ptoomey3](https://github.com/ptoomey3).
- 🌎 [GitHub's post-CSP journey](githubengineering.com/githubs-post-csp-journey/) - Written by [@ptoomey3](https://github.com/ptoomey3).

<a name="evasions-waf"></a>
### WAF

- 🌎 [Web Application Firewall (WAF) Evasion Techniques](medium.com/secjuice/waf-evasion-techniques-718026d693d8) - Written by 🌎 [@secjuice](twitter.com/secjuice).
- 🌎 [Web Application Firewall (WAF) Evasion Techniques #2](medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - Written by 🌎 [@secjuice](twitter.com/secjuice).
- 🌎 [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - Written by 🌎 [@Brett Buerhaus](twitter.com/bbuerhaus).
- 🌎 [How to bypass libinjection in many WAF/NGWAF](medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f) - Written by 🌎 [@d0znpp](medium.com/@d0znpp).

<a name="evasions-jsmvc"></a>
### JSMVC

- [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="evasions-authentication"></a>
### Authentication

- [Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - Written by 🌎 [@malerisch](twitter.com/malerisch) and 🌎 [@steventseeley](twitter.com/steventseeley).

## Tricks

<a name="tricks-csrf"></a>
### CSRF

- 🌎 [Neat tricks to bypass CSRF-protection](zhuanlan.zhihu.com/p/32716181) - Written by 🌎 [Twosecurity](twosecurity.io/).
- 🌎 [Exploiting CSRF on JSON endpoints with Flash and redirects](blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b) - Written by 🌎 [@riyazwalikar](blog.appsecco.com/@riyazwalikar).
- <b><code>&nbsp;&nbsp;&nbsp;323⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;49🍴</code></b> [Stealing CSRF tokens with CSS injection (without iFrames)](https://github.com/dxa4481/cssInjection)) - Written by [@dxa4481](https://github.com/dxa4481).
- 🌎 [Cracking Java’s RNG for CSRF - Javax Faces and Why CSRF Token Randomness Matters](blog.securityevaluators.com/cracking-javas-rng-for-csrf-ea9cacd231d2) - Written by 🌎 [@rramgattie](blog.securityevaluators.com/@rramgattie).
- 🌎 [If HttpOnly You Could Still CSRF… Of CORS you can!](medium.com/@_graphx/if-httponly-you-could-still-csrf-of-cors-you-can-5d7ee2c7443) - Written by 🌎 [@GraphX](twitter.com/GraphX).

<a name="tricks-clickjacking"></a>
### Clickjacking

- 🌎 [Clickjackings in Google worth 14981.7$](medium.com/@raushanraj_65039/google-clickjacking-6a04132b918a) - Written by 🌎 [@raushanraj_65039](medium.com/@raushanraj_65039).

<a name="tricks-rce"></a>
### Remote Code Execution

- 🌎 [CVE-2019-1306: ARE YOU MY INDEX?](www.thezdi.com/blog/2019/10/23/cve-2019-1306-are-you-my-index) - Written by 🌎 [@yu5k3](twitter.com/yu5k3).
- 🌎 [WebLogic RCE (CVE-2019-2725) Debug Diary](paper.seebug.org/910/) - Written by Badcode@Knownsec 404 Team.
- 🌎 [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - Written by 🌎 [@breenmachine](twitter.com/@breenmachine).
- 🌎 [Exploiting Node.js deserialization bug for Remote Code Execution](opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - Written by 🌎 [OpSecX](opsecx.com/index.php/author/ajinabraham/).
- 🌎 [DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE](www.ambionics.io/blog/drupal-services-module-rce) - Written by 🌎 [Ambionics Security](www.ambionics.io/).
- 🌎 [How we exploited a remote code execution vulnerability in math.js](capacitorset.github.io/mathjs/) - Written by [@capacitorset](https://github.com/capacitorset).
- [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
- 🌎 [Evil Teacher: Code Injection in Moodle](blog.ripstech.com/2018/moodle-remote-code-execution/) - Written by 🌎 [RIPS Technologies](www.ripstech.com/).
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
- 🌎 [$36k Google App Engine RCE](sites.google.com/site/testsitehacking/-36k-google-app-engine-rce) - Written by 🌎 [Ezequiel Pereira](sites.google.com/site/testsitehacking/).
- 🌎 [Poor RichFaces](codewhitesec.blogspot.com/2018/05/poor-richfaces.html) - Written by 🌎 [CODE WHITE](www.code-white.com/).
- 🌎 [Remote Code Execution on a Facebook server](blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) - Written by 🌎 [@blaklis_](twitter.com/blaklis_).

<a name="tricks-xss"></a>
### XSS

- 🌎 [Exploiting XSS with 20 characters limitation](jlajara.gitlab.io/posts/2019/11/30/XSS_20_characters.html) - Written by 🌎 [Jorge Lajara](jlajara.gitlab.io/).
- 🌎 [Upgrade self XSS to Exploitable XSS an 3 Ways Technic](www.hahwul.com/2019/11/upgrade-self-xss-to-exploitable-xss.html) - Written by 🌎 [HAHWUL](www.hahwul.com/).
- 🌎 [XSS without parentheses and semi-colons](portswigger.net/blog/xss-without-parentheses-and-semi-colons) - Written by 🌎 [@garethheyes](twitter.com/garethheyes).
- 🌎 [XSS-Auditor — the protector of unprotected and the deceiver of protected.](medium.com/bugbountywriteup/xss-auditor-the-protector-of-unprotected-f900a5e15b7b) - Written by 🌎 [@terjanq](medium.com/@terjanq).
- 🌎 [Query parameter reordering causes redirect page to render unsafe URL](hackerone.com/reports/293689) - Written by 🌎 [kenziy](hackerone.com/kenziy).
- [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).
- 🌎 [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.u50nrzhas) - Written by 🌎 [@marin_m](medium.com/@marin_m).
- 🌎 [DON'T TRUST THE DOM: BYPASSING XSS MITIGATIONS VIA SCRIPT GADGETS](www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - Written by 🌎 [Sebastian Lekies](twitter.com/slekies), 🌎 [Krzysztof Kotowicz](twitter.com/kkotowicz), and 🌎 [Eduardo Vela](twitter.com/sirdarckcat).
- [Uber XSS via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - Written by [zhchbin](http://zhchbin.github.io/).
- [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth14.html) - Written by [StamOne_](http://stamone-bug-bounty.blogspot.tw/).
- 🌎 [Stored XSS on Facebook](opnsec.com/2018/03/stored-xss-on-facebook/) - Written by 🌎 [Enguerran Gillier](opnsec.com/).
- 🌎 [XSS in Google Colaboratory + CSP bypass](blog.bentkowski.info/2018/06/xss-in-google-colaboratory-csp-bypass.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [Another XSS in Google Colaboratory](blog.bentkowski.info/2018/09/another-xss-in-google-colaboratory.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [</script> is filtered ?](twitter.com/strukt93/status/931586377665331200) - Written by 🌎 [@strukt93](twitter.com/strukt93).
- 🌎 [$20000 Facebook DOM XSS](vinothkumar.me/20000-facebook-dom-xss/) - Written by 🌎 [@vinodsparrow](twitter.com/vinodsparrow).

<a name="tricks-sql-injection"></a>
### SQL Injection

- 🌎 [MySQL Error Based SQL Injection Using EXP](www.exploit-db.com/docs/english/37953-mysql-error-based-sql-injection-using-exp.pdf) - Written by 🌎 [@osandamalith](twitter.com/osandamalith).
- [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - Written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).
- [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - Written by [Orange](http://blog.orange.tw/).
- 🌎 [Making a Blind SQL Injection a little less blind](medium.com/@tomnomnom/making-a-blind-sql-injection-a-little-less-blind-428dcb614ba8) - Written by 🌎 [TomNomNom](twitter.com/TomNomNom).
- 🌎 [Red Team Tales 0x01: From MSSQL to RCE](www.tarlogic.com/en/blog/red-team-tales-0x01/) - Written by 🌎 [Tarlogic](www.tarlogic.com/en/cybersecurity-blog/).
- 🌎 [SQL INJECTION AND POSTGRES - AN ADVENTURE TO EVENTUAL RCE](pulsesecurity.co.nz/articles/postgres-sqli) - Written by [@denandz](https://github.com/denandz).

<a name="tricks-nosql-injection"></a>
### NoSQL Injection

- [GraphQL NoSQL Injection Through JSON Types](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/) - Written by [Pete](http://www.petecorey.com/work/).

<a name="tricks-ftp-injection"></a>
### FTP Injection

- 🌎 [XML Out-Of-Band Data Retrieval](media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by 🌎 [@a66at](twitter.com/a66at) and Alexey Osipov.
- [XXE OOB exploitation at Java 1.7+](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - Written by [Ivan Novikov](http://lab.onsec.ru/).

<a name="tricks-xxe"></a>
### XXE

- 🌎 [Evil XML with two encodings](mohemiv.com/all/evil-xml/) - Written by 🌎 [Arseniy Sharoglazov](mohemiv.com/).
- [XXE in WeChat Pay Sdk ( WeChat leave a backdoor on merchant websites)](http://seclists.org/fulldisclosure/2018/Jul/3) - Written by 🌎 [Rose Jackcode](twitter.com/codeshtool).
- 🌎 [XML Out-Of-Band Data Retrieval](media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by Timur Yunusov and Alexey Osipov.
- [XXE OOB exploitation at Java 1.7+ (2014)](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html): Exfiltration using FTP protocol - Written by 🌎 [Ivan Novikov](twitter.com/d0znpp/).
- 🌎 [XXE OOB extracting via HTTP+FTP using single opened port](skavans.ru/en/2017/12/02/xxe-oob-extracting-via-httpftp-using-single-opened-port/) - Written by 🌎 [skavans](skavans.ru/).
- 🌎 [What You Didn't Know About XML External Entities Attacks](2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf) - Written by 🌎 [Timothy D. Morgan](twitter.com/ecbftw).
- 🌎 [Pre-authentication XXE vulnerability in the Services Drupal module](www.synacktiv.com/ressources/synacktiv_drupal_xxe_services.pdf) -  Written by 🌎 [Renaud Dubourguais](twitter.com/_m0bius).
- 🌎 [Forcing XXE Reflection through Server Error Messages](blog.netspi.com/forcing-xxe-reflection-server-error-messages/) - Written by 🌎 [Antti Rantasaari](blog.netspi.com/author/antti-rantasaari/).
- 🌎 [Exploiting XXE with local DTD files](mohemiv.com/all/exploiting-xxe-with-local-dtd-files/) - Written by 🌎 [Arseniy Sharoglazov](twitter.com/_mohemiv).
- 🌎 [Automating local DTD discovery for XXE exploitation](www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation) - Written by 🌎 [Philippe Arteau](twitter.com/h3xstream).

<a name="tricks-ssrf"></a>
### SSRF

- [AWS takeover through SSRF in JavaScript](http://10degres.net/aws-takeover-through-ssrf-in-javascript/) - Written by [Gwen](http://10degres.net/).
- 🌎 [SSRF in Exchange leads to ROOT access in all instances](hackerone.com/reports/341876) - Written by 🌎 [@0xacb](twitter.com/0xacb).
- 🌎 [SSRF to ROOT Access](hackerone.com/reports/341876) - A $25k bounty for SSRF leading to ROOT Access in all instances by 🌎 [0xacb](hackerone.com/0xacb).
- 🌎 [PHP SSRF Techniques](medium.com/secjuice/php-ssrf-techniques-9d422cb28d51) - Written by 🌎 [@themiddleblue](medium.com/@themiddleblue).
- 🌎 [SSRF in https://imgur.com/vidgif/url](hackerone.com/reports/115748) - Written by 🌎 [aesteral](hackerone.com/aesteral).
- 🌎 [All you need to know about SSRF and how may we write tools to do auto-detect](www.auxy.xyz/web%20security/2017/07/06/all-ssrf-knowledge.html) - Written by 🌎 [@Auxy233](twitter.com/Auxy233).
- 🌎 [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - Written by [Orange](http://blog.orange.tw/).
- [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - Written by [xl7dev](http://blog.safebuff.com/).
- 🌎 [Into the Borg – SSRF inside Google production network](opnsec.com/2018/07/into-the-borg-ssrf-inside-google-production-network/) - Written by 🌎 [opnsec](opnsec.com/).
- 🌎 [Piercing the Veil: Server Side Request Forgery to NIPRNet access](medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a) - Written by 🌎 [Alyssa Herrera](medium.com/@alyssa.o.herrera).

<a name="tricks-web-cache-poisoning"></a>
### Web Cache Poisoning

- 🌎 [Bypassing Web Cache Poisoning Countermeasures](portswigger.net/blog/bypassing-web-cache-poisoning-countermeasures) - Written by 🌎 [@albinowax](twitter.com/albinowax).
- 🌎 [Cache poisoning and other dirty tricks](lab.wallarm.com/cache-poisoning-and-other-dirty-tricks-120468f1053f) - Written by 🌎 [Wallarm](wallarm.com/).

<a name="tricks-header-injection"></a>
### Header Injection

- [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by 🌎 [Timothy Morgan](plus.google.com/105917618099766831589).

<a name="tricks-url"></a>
### URL

- 🌎 [Some Problems Of URLs](noncombatant.org/2017/11/07/problems-of-urls/) - Written by 🌎 [Chris Palmer](noncombatant.org/about/).
- 🌎 [Phishing with Unicode Domains](www.xudongz.com/blog/2017/idn-phishing/) - Written by 🌎 [Xudong Zheng](www.xudongz.com/).
- 🌎 [Unicode Domains are bad and you should feel bad for supporting them](www.vgrsec.com/post20170219.html) - Written by 🌎 [VRGSEC](www.vgrsec.com/).
- [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - Written by [Sergey Bobrov](http://blog.blackfan.ru/).

<a name="tricks-deserialization"></a>
### Deserialization

- 🌎 [ASP.NET resource files (.RESX) and deserialisation issues](www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/) - Written by 🌎 [@irsdl](twitter.com/irsdl).

<a name="tricks-oauth"></a>
### OAuth

- 🌎 [Facebook OAuth Framework Vulnerability](www.amolbaikar.com/facebook-oauth-framework-vulnerability/) - Written by 🌎 [@AmolBaikar](twitter.com/AmolBaikar).

<a name="tricks-others"></a>
### Others

- 🌎 [How I hacked Google’s bug tracking system itself for $15,600 in bounties](medium.com/free-code-camp/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5) - Written by 🌎 [@alex.birsan](medium.com/@alex.birsan).
- 🌎 [Some Tricks From My Secret Group](www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - Written by 🌎 [phithon](www.leavesongs.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;42⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [Inducing DNS Leaks in Onion Web Services](https://github.com/epidemics-scepticism/writing/blob/master/onion-dns-leaks.md)) - Written by [@epidemics-scepticism](https://github.com/epidemics-scepticism).
- 🌎 [Stored XSS, and SSRF in Google using the Dataset Publishing Language](s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html) - Written by 🌎 [@signalchaos](twitter.com/signalchaos).

## Browser Exploitation

### Frontend (like SOP bypass, URL spoofing, and something like that)

- 🌎 [The world of Site Isolation and compromised renderer](speakerdeck.com/shhnjk/the-world-of-site-isolation-and-compromised-renderer) - Written by 🌎 [@shhnjk](twitter.com/shhnjk).
- 🌎 [The Cookie Monster in Your Browsers](speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers) - Written by 🌎 [@filedescriptor](twitter.com/filedescriptor).
- 🌎 [Bypassing Mobile Browser Security For Fun And Profit](www.blackhat.com/docs/asia-16/materials/asia-16-Baloch-Bypassing-Browser-Security-Policies-For-Fun-And-Profit-wp.pdf) - Written by 🌎 [@rafaybaloch](twitter.com/@rafaybaloch).
- 🌎 [The inception bar: a new phishing method](jameshfisher.com/2019/04/27/the-inception-bar-a-new-phishing-method/) - Written by 🌎 [jameshfisher](jameshfisher.com/).
- [JSON hijacking for the modern web](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [IE11 Information disclosure - local file detection](www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - Written by James Lee.
- 🌎 [SOP bypass / UXSS – Stealing Credentials Pretty Fast (Edge)](www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - Written by 🌎 [Manuel](twitter.com/magicmac2000).
- 🌎 [Особенности Safari в client-side атаках](bo0om.ru/safari-client-side) - Written by 🌎 [Bo0oM](bo0om.ru/author/admin).
- 🌎 [How do we Stop Spilling the Beans Across Origins?](docs.google.com/document/d/1cbL-X0kV_tQ5rL8XJ3lXkV-j0pt_CfTu5ZSzYrncPDc/) - Written by [aaj at google.com](aaj@google.com) and [mkwst at google.com](mkwst@google.com).
- 🌎 [Setting arbitrary request headers in Chromium via CRLF injection](blog.bentkowski.info/2018/06/setting-arbitrary-request-headers-in.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [I’m harvesting credit card numbers and passwords from your site. Here’s how.](hackernoon.com/im-harvesting-credit-card-numbers-and-passwords-from-your-site-here-s-how-9a8cb347c5b5) - Written by 🌎 [David Gilbertson](hackernoon.com/@david.gilbertson).
- 🌎 [Sending arbitrary IPC messages via overriding Function.prototype.apply](hackerone.com/reports/188086) - Written by 🌎 [@kinugawamasato](twitter.com/kinugawamasato).
- 🌎 [Take Advantage of Out-of-Scope Domains in Bug Bounty Programs](ahussam.me/Take-Advantage-of-Out-of-Scope-Domains-in-Bug-Bounty/) - Written by 🌎 [@Abdulahhusam](twitter.com/Abdulahhusam).

### Backend (core of Browser implementation, and often refers to C or C++ part)

- 🌎 [Breaking UC Browser](habr.com/en/company/drweb/blog/452076/) - Written by 🌎 [Доктор Веб](www.drweb.ru/).
- [Attacking JavaScript Engines - A case study of JavaScriptCore and CVE-2016-4622](http://www.phrack.org/papers/attacking_javascript_engines.html) - Written by [phrack@saelo.net](phrack@saelo.net).
- [Three roads lead to Rome](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - Written by 🌎 [@holynop](twitter.com/holynop).
- 🌎 [Exploiting a V8 OOB write.](halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - Written by 🌎 [@halbecaf](twitter.com/halbecaf).
- 🌎 [SSD Advisory – Chrome Turbofan Remote Code Execution](blogs.securiteam.com/index.php/archives/3379) - Written by 🌎 [SecuriTeam Secure Disclosure (SSD)](blogs.securiteam.com/).
- 🌎 [Look Mom, I don't use Shellcode - Browser Exploitation Case Study for Internet Explorer 11](labs.bluefrostsecurity.de/files/Look_Mom_I_Dont_Use_Shellcode-WP.pdf) - Written by [@moritzj](http://twitter.com/moritzj).
- 🌎 [PUSHING WEBKIT'S BUTTONS WITH A MOBILE PWN2OWN EXPLOIT](www.zerodayinitiative.com/blog/2018/2/12/pushing-webkits-buttons-with-a-mobile-pwn2own-exploit) - Written by 🌎 [@wanderingglitch](twitter.com/wanderingglitch).
- 🌎 [A Methodical Approach to Browser Exploitation](blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/) - Written by 🌎 [RET2 SYSTEMS, INC](blog.ret2.io/).
- 🌎 [CVE-2017-2446 or JSC::JSGlobalObject::isHavingABadTime.](doar-e.github.io/blog/2018/07/14/cve-2017-2446-or-jscjsglobalobjectishavingabadtime/) - Written by 🌎 [Diary of a reverse-engineer](doar-e.github.io/).
- 🌎 [CLEANLY ESCAPING THE CHROME SANDBOX](theori.io/research/escaping-chrome-sandbox) - Written by 🌎 [@tjbecker_](twitter.com/tjbecker_).
- 🌎 [A Methodical Approach to Browser Exploitation](blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/) - Written by 🌎 [@PatrickBiernat](twitter.com/PatrickBiernat), 🌎 [@gaasedelen](twitter.com/gaasedelen) and 🌎 [@itszn13](twitter.com/itszn13).

## PoCs

<a name="pocs-database"></a>
### Database

- <b><code>&nbsp;&nbsp;2314⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;404🍴</code></b> [js-vuln-db](https://github.com/tunz/js-vuln-db)) - Collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
- <b><code>&nbsp;&nbsp;3473⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;725🍴</code></b> [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc)) - Curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).
- <b><code>&nbsp;&nbsp;2484⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;968🍴</code></b> [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP)) - 各种漏洞poc、Exp的收集或编写 by [@coffeehb](https://github.com/coffeehb).
- <b><code>&nbsp;&nbsp;&nbsp;698⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;85🍴</code></b> [uxss-db](https://github.com/Metnew/uxss-db)) - Collection of UXSS CVEs with PoCs by [@Metnew](https://github.com/Metnew).
- 🌎 [SPLOITUS](sploitus.com/) - Exploits & Tools Search Engine by 🌎 [@i_bo0om](twitter.com/i_bo0om).
- 🌎 [Exploit Database](www.exploit-db.com/) - ultimate archive of Exploits, Shellcode, and Security Papers by 🌎 [Offensive Security](www.offensive-security.com/).

## Cheetsheets

- 🌎 [XSS Cheat Sheet - 2018 Edition](leanpub.com/xss) - Written by 🌎 [@brutelogic](twitter.com/brutelogic).
- <b><code>&nbsp;&nbsp;&nbsp;123⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [Capture the Flag CheatSheet](https://github.com/uppusaikiran/awesome-ctf-cheatsheet)) - Written by [@uppusaikiran](https://github.com/uppusaikiran).

## Tools

<a name="tools-auditing"></a>
### Auditing

- <b><code>&nbsp;13073⭐</code></b> <b><code>&nbsp;&nbsp;2005🍴</code></b> [prowler](https://github.com/Alfresco/prowler)) - Tool for AWS security assessment, auditing and hardening by [@Alfresco](https://github.com/Alfresco).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [slurp](https://github.com/hehnope/slurp)) - Evaluate the security of S3 buckets by [@hehnope](https://github.com/hehnope).
- <b><code>&nbsp;&nbsp;&nbsp;634⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;169🍴</code></b> [A2SV](https://github.com/hahwul/a2sv)) - Auto Scanning to SSL Vulnerability by [@hahwul](https://github.com/hahwul).

<a name="tools-command-injection"></a>
### Command Injection

- <b><code>&nbsp;&nbsp;5631⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;921🍴</code></b> [commix](https://github.com/commixproject/commix)) - Automated All-in-One OS command injection and exploitation tool by [@commixproject](https://github.com/commixproject).

<a name="tools-reconnaissance"></a>
### Reconnaissance

<a name="tools-osint"></a>
#### OSINT - Open-Source Intelligence

- 🌎 [Shodan](www.shodan.io/) - Shodan is the world's first search engine for Internet-connected devices by 🌎 [@shodanhq](twitter.com/shodanhq).
- 🌎 [Censys](censys.io/) - Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet by 🌎 [University of Michigan](umich.edu/).
- 🌎 [urlscan.io](urlscan.io/) - Service which analyses websites and the resources they request by 🌎 [@heipei](twitter.com/heipei).
- 🌎 [ZoomEye](www.zoomeye.org/) - Cyberspace Search Engine by 🌎 [@zoomeye_team](twitter.com/zoomeye_team).
- 🌎 [FOFA](fofa.so/?locale=en) - Cyberspace Search Engine by [BAIMAOHUI](http://baimaohui.net/).
- 🌎 [NSFOCUS](nti.nsfocus.com/) - THREAT INTELLIGENCE PORTAL by NSFOCUS GLOBAL.
- <b><code>&nbsp;12690⭐</code></b> <b><code>&nbsp;&nbsp;1671🍴</code></b> [Photon](https://github.com/s0md3v/Photon)) - Incredibly fast crawler designed for OSINT by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;3434⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;609🍴</code></b> [FOCA](https://github.com/ElevenPaths/FOCA)) - FOCA (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans by 🌎 [ElevenPaths](www.elevenpaths.com/index.html).
- [SpiderFoot](http://www.spiderfoot.net/) - Open source footprinting and intelligence-gathering tool by 🌎 [@binarypool](twitter.com/binarypool).
- <b><code>&nbsp;&nbsp;2290⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;299🍴</code></b> [xray](https://github.com/evilsocket/xray)) - XRay is a tool for recon, mapping and OSINT gathering from public networks by [@evilsocket](https://github.com/evilsocket).
- <b><code>&nbsp;&nbsp;6139⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;846🍴</code></b> [gitrob](https://github.com/michenriksen/Gitrob)) - Reconnaissance tool for GitHub organizations by [@michenriksen](https://github.com/michenriksen).
- <b><code>&nbsp;&nbsp;2144⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;490🍴</code></b> [GSIL](https://github.com/FeeiCN/GSIL)) - Github Sensitive Information Leakage（Github敏感信息泄露）by [@FeeiCN](https://github.com/FeeiCN).
- <b><code>&nbsp;&nbsp;&nbsp;795⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;162🍴</code></b> [raven](https://github.com/0x09AL/raven)) - raven is a Linkedin information gathering tool that can be used by pentesters to gather information about an organization employees using Linkedin by [@0x09AL](https://github.com/0x09AL).
- <b><code>&nbsp;&nbsp;2008⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;353🍴</code></b> [ReconDog](https://github.com/s0md3v/ReconDog)) - Reconnaissance Swiss Army Knife by [@s0md3v](https://github.com/s0md3v).
- 🌎 [Databases - start.me](start.me/p/QRENnO/databases) - Various databases which you can use for your OSINT research by 🌎 [@technisette](twitter.com/technisette).
- 🌎 [peoplefindThor](peoplefindthor.dk/) - the easy way to find people on Facebook by [postkassen](mailto:postkassen@oejvind.dk?subject=peoplefindthor.dk comments).
- <b><code>&nbsp;&nbsp;1963⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;268🍴</code></b> [tinfoleak](https://github.com/vaguileradiaz/tinfoleak)) - The most complete open-source tool for Twitter intelligence analysis by [@vaguileradiaz](https://github.com/vaguileradiaz).
- <b><code>&nbsp;&nbsp;3512⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;443🍴</code></b> [Raccoon](https://github.com/evyatarmeged/Raccoon)) - High performance offensive security tool for reconnaissance and vulnerability scanning by [@evyatarmeged](https://github.com/evyatarmeged).
- <b><code>&nbsp;&nbsp;3973⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;813🍴</code></b> [Social Mapper](https://github.com/SpiderLabs/social_mapper)) - Social Media Enumeration & Correlation Tool by Jacob Wilkin(Greenwolf) by [@SpiderLabs](https://github.com/SpiderLabs).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;40⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [espi0n/Dockerfiles](https://github.com/espi0n/Dockerfiles)) - Dockerfiles for various OSINT tools by [@espi0n](https://github.com/espi0n).

<a name="tools-sub-domain-enumeration"></a>
#### Sub Domain Enumeration

- <b><code>&nbsp;10822⭐</code></b> <b><code>&nbsp;&nbsp;2201🍴</code></b> [Sublist3r](https://github.com/aboul3la/Sublist3r)) - Sublist3r is a multi-threaded sub-domain enumeration tool for penetration testers by [@aboul3la](https://github.com/aboul3la).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;55⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [EyeWitness](https://github.com/ChrisTruncer/EyeWitness)) - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible by [@ChrisTruncer](https://github.com/ChrisTruncer).
- <b><code>&nbsp;&nbsp;3602⭐</code></b> <b><code>&nbsp;&nbsp;1011🍴</code></b> [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)) - A simple and fast sub domain brute tool for pentesters by [@lijiejie](https://github.com/lijiejie).
- <b><code>&nbsp;&nbsp;5901⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;909🍴</code></b> [AQUATONE](https://github.com/michenriksen/aquatone)) - Tool for Domain Flyovers by [@michenriksen](https://github.com/michenriksen).
- <b><code>&nbsp;&nbsp;1862⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;239🍴</code></b> [domain_analyzer](https://github.com/eldraco/domain_analyzer)) - Analyze the security of any domain by finding all the information possible by [@eldraco](https://github.com/eldraco).
- 🌎 [VirusTotal domain information](www.virustotal.com/en/documentation/searching/#getting-domain-information) - Searching for domain information by 🌎 [VirusTotal](www.virustotal.com/).
- <b><code>&nbsp;&nbsp;&nbsp;886⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;289🍴</code></b> [Certificate Transparency](https://github.com/google/certificate-transparency)) - Google's Certificate Transparency project fixes several structural flaws in the SSL certificate system by [@google](https://github.com/google).
- 🌎 [Certificate Search](crt.sh/) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to search certificate(s) by [@crtsh](https://github.com/crtsh).
- <b><code>&nbsp;&nbsp;&nbsp;183⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;52🍴</code></b> [GSDF](https://github.com/We5ter/GSDF)) - Domain searcher named GoogleSSLdomainFinder by [@We5ter](https://github.com/We5ter).

<a name="tools-code-generating"></a>
### Code Generating

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;84⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;18🍴</code></b> [VWGen](https://github.com/qazbnm456/VWGen)) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tools-fuzzing"></a>
### Fuzzing

- <b><code>&nbsp;&nbsp;6418⭐</code></b> <b><code>&nbsp;&nbsp;1402🍴</code></b> [wfuzz](https://github.com/xmendez/wfuzz)) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [charsetinspect](https://github.com/hack-all-the-things/charsetinspect)) - Script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).
- <b><code>&nbsp;&nbsp;&nbsp;144⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;45🍴</code></b> [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator)) - Simple tool to convert the IP to a DWORD IP by [@OsandaMalith](https://github.com/OsandaMalith).
- <b><code>&nbsp;&nbsp;1769⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;285🍴</code></b> [domato](https://github.com/google/domato)) - DOM fuzzer by [@google](https://github.com/google).
- <b><code>&nbsp;&nbsp;8818⭐</code></b> <b><code>&nbsp;&nbsp;2122🍴</code></b> [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
- <b><code>&nbsp;&nbsp;1978⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;271🍴</code></b> [dirhunt](https://github.com/Nekmo/dirhunt)) - Web crawler optimized for searching and analyzing the directory structure of a site by [@nekmo](https://github.com/Nekmo).
- 🌎 [ssltest](www.ssllabs.com/ssltest/) - Online service that performs a deep analysis of the configuration of any SSL web server on the public internet. Provided by 🌎 [Qualys SSL Labs](www.ssllabs.com).
- <b><code>&nbsp;&nbsp;3271⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;525🍴</code></b> [fuzz.txt](https://github.com/Bo0oM/fuzz.txt)) - Potentially dangerous files by [@Bo0oM](https://github.com/Bo0oM).

<a name="tools-scanning"></a>
### Scanning

- <b><code>&nbsp;&nbsp;9470⭐</code></b> <b><code>&nbsp;&nbsp;1330🍴</code></b> [wpscan](https://github.com/wpscanteam/wpscan)) - WPScan is a black box WordPress vulnerability scanner by [@wpscanteam](https://github.com/wpscanteam).
- <b><code>&nbsp;&nbsp;&nbsp;247⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;70🍴</code></b> [JoomlaScan](https://github.com/drego85/JoomlaScan)) - Free software to find the components installed in Joomla CMS, built out of the ashes of Joomscan by [@drego85](https://github.com/drego85).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [WAScan](https://github.com/m4ll0k/WAScan)) - Is an open source web application security scanner that uses "black-box" method, created by [@m4ll0k](https://github.com/m4ll0k).
- <b><code>&nbsp;27134⭐</code></b> <b><code>&nbsp;&nbsp;3179🍴</code></b> [Nuclei](https://github.com/projectdiscovery/nuclei)) - Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use by [@projectdiscovery](https://github.com/projectdiscovery).

<a name="tools-penetration-testing"></a>
### Penetration Testing

- 🌎 [Burp Suite](portswigger.net/burp/) - Burp Suite is an integrated platform for performing security testing of web applications by 🌎 [portswigger](portswigger.net/).
- <b><code>&nbsp;&nbsp;1850⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;398🍴</code></b> [TIDoS-Framework](https://github.com/theInfectedDrake/TIDoS-Framework)) - A comprehensive web application audit framework to cover up everything from Reconnaissance and OSINT to Vulnerability Analysis by [@_tID](https://github.com/theInfectedDrake).
- <b><code>&nbsp;&nbsp;2639⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;411🍴</code></b> [Astra](https://github.com/flipkart-incubator/astra)) - Automated Security Testing For REST API's by [@flipkart-incubator](https://github.com/flipkart-incubator).
- <b><code>&nbsp;&nbsp;1219⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;195🍴</code></b> [aws_pwn](https://github.com/dagrz/aws_pwn)) - A collection of AWS penetration testing junk by [@dagrz](https://github.com/dagrz).
- 🌎 [grayhatwarfare](buckets.grayhatwarfare.com/) - Public buckets by [grayhatwarfare](http://www.grayhatwarfare.com/).

<a name="tools-offensive"></a>
### Offensive

<a name="tools-xss"></a>
#### XSS - Cross-Site Scripting

- <b><code>&nbsp;10735⭐</code></b> <b><code>&nbsp;&nbsp;2342🍴</code></b> [beef](https://github.com/beefproject/beef)) - The Browser Exploitation Framework Project by 🌎 [beefproject](beefproject.com).
- <b><code>&nbsp;&nbsp;&nbsp;532⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;136🍴</code></b> [JShell](https://github.com/s0md3v/JShell)) - Get a JavaScript shell with XSS by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;14754⭐</code></b> <b><code>&nbsp;&nbsp;2068🍴</code></b> [XSStrike](https://github.com/s0md3v/XSStrike)) - XSStrike is a program which can fuzz and bruteforce parameters for XSS. It can also detect and bypass WAFs by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;2202⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;381🍴</code></b> [xssor2](https://github.com/evilcos/xssor2)) - XSS'OR - Hack with JavaScript by [@evilcos](https://github.com/evilcos).
- 🌎 [csp evaluator](csper.io/evaluator) - A tool for evaluating content-security-policies by [Csper](http://csper.io).

<a name="tools-sql-injection"></a>
#### SQL Injection

- <b><code>&nbsp;36652⭐</code></b> <b><code>&nbsp;&nbsp;6205🍴</code></b> [sqlmap](https://github.com/sqlmapproject/sqlmap)) - Automatic SQL injection and database takeover tool.

<a name="tools-template-injection"></a>
#### Template Injection

- <b><code>&nbsp;&nbsp;4118⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;688🍴</code></b> [tplmap](https://github.com/epinna/tplmap)) - Code and Server-Side Template Injection Detection and Exploitation Tool by [@epinna](https://github.com/epinna).

<a name="tools-xxe"></a>
#### XXE

- <b><code>&nbsp;&nbsp;&nbsp;647⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;113🍴</code></b> [dtd-finder](https://github.com/GoSecure/dtd-finder)) - List DTDs and generate XXE payloads using those local DTDs by [@GoSecure](https://github.com/GoSecure).

<a name="tools-csrf"></a>
#### Cross Site Request Forgery

- <b><code>&nbsp;&nbsp;1279⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;220🍴</code></b> [XSRFProbe](https://github.com/0xInfection/XSRFProbe)) - The Prime CSRF Audit & Exploitation Toolkit by [@0xInfection](https://github.com/0xinfection).

<a name="tools-ssrf"></a>
#### Server-Side Request Forgery

- 🌎 [Open redirect/SSRF payload generator](tools.intigriti.io/redirector/) - Open redirect/SSRF payload generator by 🌎 [intigriti](www.intigriti.com/).

<a name="tools-leaking"></a>
### Leaking

- <b><code>&nbsp;&nbsp;2099⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;207🍴</code></b> [HTTPLeaks](https://github.com/cure53/HTTPLeaks)) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
- <b><code>&nbsp;&nbsp;1777⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;316🍴</code></b> [dvcs-ripper](https://github.com/kost/dvcs-ripper)) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).
- <b><code>&nbsp;&nbsp;&nbsp;326⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;58🍴</code></b> [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage)) - Pillage web accessible GIT, HG and BZR repositories by [@evilpacket](https://github.com/evilpacket).
- <b><code>&nbsp;&nbsp;2153⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;431🍴</code></b> [GitMiner](https://github.com/UnkL4b/GitMiner)) - Tool for advanced mining for content on Github by [@UnkL4b](https://github.com/UnkL4b).
- <b><code>&nbsp;25029⭐</code></b> <b><code>&nbsp;&nbsp;1926🍴</code></b> [gitleaks](https://github.com/zricethezav/gitleaks)) - Searches full repo history for secrets and keys by [@zricethezav](https://github.com/zricethezav).
- <b><code>&nbsp;&nbsp;3246⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;430🍴</code></b> [CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging)) - Chrome extension and Express server that exploits keylogging abilities of CSS by [@maxchehab](https://github.com/maxchehab).
- <b><code>&nbsp;&nbsp;&nbsp;108⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22🍴</code></b> [pwngitmanager](https://github.com/allyshka/pwngitmanager)) - Git manager for pentesters by [@allyshka](https://github.com/allyshka).
- <b><code>&nbsp;&nbsp;2103⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;230🍴</code></b> [snallygaster](https://github.com/hannob/snallygaster)) - Tool to scan for secret files on HTTP servers by [@hannob](https://github.com/hannob).
- <b><code>&nbsp;&nbsp;4283⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;652🍴</code></b> [LinkFinder](https://github.com/GerbenJavado/LinkFinder)) - Python script that finds endpoints in JavaScript files by [@GerbenJavado](https://github.com/GerbenJavado).

<a name="tools-detecting"></a>
### Detecting

- 🌎 [sqlchop](sqlchop.chaitin.cn/) - SQL injection detection engine by [chaitin](http://chaitin.com).
- 🌎 [xsschop](xsschop.chaitin.cn/) - XSS detection engine by [chaitin](http://chaitin.com).
- <b><code>&nbsp;&nbsp;4072⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;433🍴</code></b> [retire.js](https://github.com/RetireJS/retire.js)) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).
- <b><code>&nbsp;&nbsp;&nbsp;477⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;97🍴</code></b> [malware-jail](https://github.com/HynekPetrak/malware-jail)) - Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction by [@HynekPetrak](https://github.com/HynekPetrak).
- <b><code>&nbsp;&nbsp;&nbsp;653⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;89🍴</code></b> [repo-supervisor](https://github.com/auth0/repo-supervisor)) - Scan your code for security misconfiguration, search for passwords and secrets.
- <b><code>&nbsp;&nbsp;&nbsp;566⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;65🍴</code></b> [bXSS](https://github.com/LewisArdern/bXSS)) - bXSS is a simple Blind XSS application adapted from 🌎 [cure53.de/m](cure53.de/m) by [@LewisArdern](https://github.com/LewisArdern).
- <b><code>&nbsp;&nbsp;2952⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;624🍴</code></b> [OpenRASP](https://github.com/baidu/openrasp)) - An open source RASP solution actively maintained by Baidu Inc. With context-aware detection algorithm the project achieved nearly no false positives. And less than 3% performance reduction is observed under heavy server load.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [GuardRails](https://github.com/apps/guardrails)) - A GitHub App that provides security feedback in Pull Requests.

<a name="tools-preventing"></a>
### Preventing

- <b><code>&nbsp;16645⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;823🍴</code></b> [DOMPurify](https://github.com/cure53/DOMPurify)) - DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG by 🌎 [Cure53](cure53.de/).
- <b><code>&nbsp;&nbsp;5306⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;631🍴</code></b> [js-xss](https://github.com/leizongmin/js-xss)) - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist by [@leizongmin](https://github.com/leizongmin).
- <b><code>&nbsp;&nbsp;1453⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;134🍴</code></b> [Acra](https://github.com/cossacklabs/acra)) - Client-side encryption engine for SQL databases, with strong selective encryption, SQL injections prevention and intrusion detection by 🌎 [@cossacklabs](www.cossacklabs.com/).
- 🌎 [Csper](csper.io) - A set of tools for building/evaluating/monitoring content-security-policy to prevent/detect cross site scripting by 🌎 [Csper](csper.io).

<a name="tools-proxy"></a>
### Proxy

- 🌎 [Charles](www.charlesproxy.com/) - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
- <b><code>&nbsp;42355⭐</code></b> <b><code>&nbsp;&nbsp;4457🍴</code></b> [mitmproxy](https://github.com/mitmproxy/mitmproxy)) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers by [@mitmproxy](https://github.com/mitmproxy).

<a name="tools-webshell"></a>
### Webshell

- <b><code>&nbsp;&nbsp;&nbsp;446⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;92🍴</code></b> [nano](https://github.com/s0md3v/nano)) - Family of code golfed PHP shells by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;10689⭐</code></b> <b><code>&nbsp;&nbsp;5613🍴</code></b> [webshell](https://github.com/tennc/webshell)) - This is a webshell open source project by [@tennc](https://github.com/tennc).
- <b><code>&nbsp;&nbsp;3485⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;634🍴</code></b> [Weevely](https://github.com/epinna/weevely3)) - Weaponized web shell by [@epinna](https://github.com/epinna).
- <b><code>&nbsp;&nbsp;&nbsp;423⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;112🍴</code></b> [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper)) - Manage your website via terminal by [@WangYihang](https://github.com/WangYihang).
- <b><code>&nbsp;&nbsp;&nbsp;244⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;63🍴</code></b> [Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager)) - Reverse Shell Manager via Terminal [@WangYihang](https://github.com/WangYihang).
- <b><code>&nbsp;&nbsp;2003⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;249🍴</code></b> [reverse-shell](https://github.com/lukechilds/reverse-shell)) - Reverse Shell as a Service by [@lukechilds](https://github.com/lukechilds).
- <b><code>&nbsp;&nbsp;2446⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;473🍴</code></b> [PhpSploit](https://github.com/nil0x42/phpsploit)) - Full-featured C2 framework which silently persists on webserver via evil PHP oneliner by [@nil0x42](https://github.com/nil0x42).

<a name="tools-disassembler"></a>
### Disassembler

- <b><code>&nbsp;&nbsp;3063⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;273🍴</code></b> [plasma](https://github.com/plasma-disassembler/plasma)) - Plasma is an interactive disassembler for x86/ARM/MIPS by [@plasma-disassembler](https://github.com/plasma-disassembler).
- <b><code>&nbsp;23135⭐</code></b> <b><code>&nbsp;&nbsp;3167🍴</code></b> [radare2](https://github.com/radare/radare2)) - Unix-like reverse engineering framework and commandline tools by [@radare](https://github.com/radare).
- <b><code>&nbsp;&nbsp;1460⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;117🍴</code></b> [Iaitō](https://github.com/hteso/iaito)) - Qt and C++ GUI for radare2 reverse engineering framework by [@hteso](https://github.com/hteso).

<a name="tools-decompiler"></a>
### Decompiler

- [CFR](http://www.benf.org/other/cfr/) - Another java decompiler by 🌎 [@LeeAtBenf](twitter.com/LeeAtBenf).

<a name="tools-dns-rebinding"></a>
### DNS Rebinding

- <b><code>&nbsp;&nbsp;&nbsp;500⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;84🍴</code></b> [DNS Rebind Toolkit](https://github.com/brannondorsey/dns-rebind-toolkit)) - DNS Rebind Toolkit is a frontend JavaScript framework for developing DNS Rebinding exploits against vulnerable hosts and services on a local area network (LAN) by [@brannondorsey](https://github.com/brannondorsey)
- <b><code>&nbsp;&nbsp;&nbsp;493⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;72🍴</code></b> [dref](https://github.com/mwrlabs/dref)) - DNS Rebinding Exploitation Framework. Dref does the heavy-lifting for DNS rebinding by [@mwrlabs](https://github.com/mwrlabs)
- <b><code>&nbsp;&nbsp;1262⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;158🍴</code></b> [Singularity of Origin](https://github.com/nccgroup/singularity)) - It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine by [@nccgroup](https://github.com/nccgroup)
- <b><code>&nbsp;&nbsp;&nbsp;655⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;97🍴</code></b> [Whonow DNS Server](https://github.com/brannondorsey/whonow)) - A malicious DNS server for executing DNS Rebinding attacks on the fly by [@brannondorsey](https://github.com/brannondorsey)

<a name="tools-others"></a>
### Others

- 🌎 [Dnslogger](wiki.skullsecurity.org/index.php?title=Dnslogger) - DNS Logger by [@iagox86](https://github.com/iagox86).
- <b><code>&nbsp;34091⭐</code></b> <b><code>&nbsp;&nbsp;3846🍴</code></b> [CyberChef](https://github.com/gchq/CyberChef)) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis - by [@GCHQ](https://github.com/gchq).
- <b><code>&nbsp;&nbsp;&nbsp;151⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26🍴</code></b> [ntlm_challenger](https://github.com/b17zr/ntlm_challenger)) - Parse NTLM over HTTP challenge messages by [@b17zr](https://github.com/b17zr).
- <b><code>&nbsp;&nbsp;&nbsp;211⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20🍴</code></b> [cefdebug](https://github.com/taviso/cefdebug)) - Minimal code to connect to a CEF debugger by [@taviso](https://github.com/taviso).
- <b><code>&nbsp;&nbsp;1664⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;268🍴</code></b> [ctftool](https://github.com/taviso/ctftool)) - Interactive CTF Exploration Tool by [@taviso](https://github.com/taviso).

## Social Engineering Database

- 🌎 [haveibeenpwned](haveibeenpwned.com/) - Check if you have an account that has been compromised in a data breach by 🌎 [Troy Hunt](www.troyhunt.com/).

## Blogs

- [Orange](http://blog.orange.tw/) - Taiwan's talented web penetrator.
- 🌎 [leavesongs](www.leavesongs.com/) - China's talented web penetrator.
- [James Kettle](http://albinowax.skeletonscribe.net/) - Head of Research at 🌎 [PortSwigger Web Security](portswigger.net/).
- 🌎 [Broken Browser](www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
- 🌎 [Scrutiny](datarift.blogspot.tw/) - Internet Security through Web Browsers by Dhiraj Mishra.
- 🌎 [BRETT BUERHAUS](buer.haus/) - Vulnerability disclosures and rambles on application security.
- 🌎 [n0tr00t](www.n0tr00t.com/) - ~# n0tr00t Security Team.
- 🌎 [OpnSec](opnsec.com/) - Open Mind Security!
- 🌎 [RIPS Technologies](blog.ripstech.com/tags/security/) - Write-ups for PHP vulnerabilities.
- [0Day Labs](http://blog.0daylabs.com/) - Awesome bug-bounty and challenges writeups.
- 🌎 [Blog of Osanda](osandamalith.com/) - Security Researching and Reverse Engineering.

## Twitter Users

- 🌎 [@HackwithGitHub](twitter.com/HackwithGithub) - Initiative to showcase open source hacking tools for hackers and pentesters
- 🌎 [@filedescriptor](twitter.com/filedescriptor) - Active penetrator often tweets and writes useful articles
- 🌎 [@cure53berlin](twitter.com/cure53berlin) - 🌎 [Cure53](cure53.de/) is a German cybersecurity firm.
- 🌎 [@XssPayloads](twitter.com/XssPayloads) - The wonderland of JavaScript unexpected usages, and more.
- 🌎 [@kinugawamasato](twitter.com/kinugawamasato) - Japanese web penetrator.
- 🌎 [@h3xstream](twitter.com/h3xstream/) - Security Researcher, interested in web security, crypto, pentest, static analysis but most of all, samy is my hero.
- 🌎 [@garethheyes](twitter.com/garethheyes) - English web penetrator.
- 🌎 [@hasegawayosuke](twitter.com/hasegawayosuke) - Japanese javascript security researcher.
- 🌎 [@shhnjk](twitter.com/shhnjk) - Web and Browsers Security Researcher.

## Practices

<a name="practices-application"></a>
### Application

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [OWASP Juice Shop](https://github.com/bkimminich/juice-shop)) - Probably the most modern and sophisticated insecure web application - Written by [@bkimminich](https://github.com/bkimminich) and the 🌎 [@owasp_juiceshop](twitter.com/owasp_juiceshop) team.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;59⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [BadLibrary](https://github.com/SecureSkyTechnology/BadLibrary)) - Vulnerable web application for training - Written by [@SecureSkyTechnology](https://github.com/SecureSkyTechnology).
- [Hackxor](http://hackxor.net/) - Realistic web application hacking game - Written by 🌎 [@albinowax](twitter.com/albinowax).
- [SELinux Game](http://selinuxgame.org/) - Learn SELinux by doing. Solve Puzzles, show skillz - Written by 🌎 [@selinuxgame](twitter.com/selinuxgame).
- 🌎 [Portswigger Web Security Academy](portswigger.net/web-security) - Free trainings and labs - Written by 🌎 [PortSwigger](portswigger.net/).

<a name="practices-aws"></a>
### AWS

- [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge - Written by 🌎 [@0xdabbad00](twitter.com/0xdabbad00).
- <b><code>&nbsp;&nbsp;3482⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;737🍴</code></b> [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)) - Rhino Security Labs' "Vulnerable by Design" AWS infrastructure setup tool  - Written by [@RhinoSecurityLabs](https://github.com/RhinoSecurityLabs).

<a name="practices-xss"></a>
### XSS

- 🌎 [XSS game](xss-game.appspot.com/) - Google XSS Challenge - Written by Google.
- [prompt(1) to win](http://prompt.ml/) - Complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels) - Written by [@cure53](https://github.com/cure53).
- 🌎 [alert(1) to win](alf.nu/alert1) - Series of XSS challenges - Written by 🌎 [@steike](twitter.com/steike).
- [XSS Challenges](http://xss-quiz.int21h.jp/) - Series of XSS challenges - Written by yamagata21.

<a name="practices-modsecurity"></a>
### ModSecurity / OWASP ModSecurity Core Rule Set

- 🌎 [ModSecurity / OWASP ModSecurity Core Rule Set](www.netnea.com/cms/apache-tutorials/) - Series of tutorials to install, configure and tune ModSecurity and the Core Rule Set - Written by 🌎 [@ChrFolini](twitter.com/ChrFolini).

## Community

- 🌎 [Reddit](www.reddit.com/r/websecurity/)
- [Stack Overflow](http://stackoverflow.com/questions/tagged/security)

## Miscellaneous

- <b><code>&nbsp;&nbsp;5415⭐</code></b> <b><code>&nbsp;&nbsp;1018🍴</code></b> [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty)) - Comprehensive curated list of available Bug Bounty & Disclosure Programs and write-ups by [@djadmin](https://github.com/djadmin).
- <b><code>&nbsp;&nbsp;4066⭐</code></b> <b><code>&nbsp;&nbsp;1014🍴</code></b> [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference)) - List of bug bounty write-up that is categorized by the bug nature by [@ngalongc](https://github.com/ngalongc).
- 🌎 [Google VRP and Unicorns](sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns) - Written by 🌎 [Daniel Stelter-Gliese](www.linkedin.com/in/daniel-stelter-gliese-170a70a2/).
- [Brute Forcing Your Facebook Email and Phone Number](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html) - Written by [PwnDizzle](http://pwndizzle.blogspot.jp/).
- [Pentest + Exploit dev Cheatsheet wallpaper](http://i.imgur.com/Mr9pvq9.jpg) - Penetration Testing and Exploit Dev CheatSheet.
- [The Definitive Security Data Science and Machine Learning Guide](http://www.covert.io/the-definitive-security-datascience-and-machinelearning-guide/) - Written by JASON TROS.
- <b><code>&nbsp;&nbsp;4198⭐</code></b> <b><code>&nbsp;&nbsp;2082🍴</code></b> [EQGRP](https://github.com/x0rz/EQGRP)) - Decrypted content of eqgrp-auction-file.tar.xz by [@x0rz](https://github.com/x0rz).
- <b><code>&nbsp;&nbsp;1276⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;76🍴</code></b> [notes](https://github.com/ChALkeR/notes)) - Some public notes by [@ChALkeR](https://github.com/ChALkeR).
- 🌎 [A glimpse into GitHub's Bug Bounty workflow](githubengineering.com/githubs-bug-bounty-workflow/) - Written by [@gregose](https://github.com/gregose).
- 🌎 [Cybersecurity Campaign Playbook](www.belfercenter.org/CyberPlaybook) - Written by 🌎 [Belfer Center for Science and International Affairs](www.belfercenter.org/).
- <b><code>&nbsp;&nbsp;5902⭐</code></b> <b><code>&nbsp;&nbsp;1222🍴</code></b> [Infosec_Reference](https://github.com/rmusser01/Infosec_Reference)) - Information Security Reference That Doesn't Suck by [@rmusser01](https://github.com/rmusser01).
- [Internet of Things Scanner](http://iotscanner.bullguard.com/) - Check if your internet-connected devices at home are public on Shodan by 🌎 [BullGuard](www.bullguard.com/).
- 🌎 [The Bug Hunters Methodology v2.1](docs.google.com/presentation/d/1VpRT8dFyTaFpQa9jhehtmGaC7TqQniMSYbUdlHN6VrY/edit?usp=sharing) - Written by 🌎 [@jhaddix](twitter.com/jhaddix).
- 🌎 [$7.5k Google services mix-up](sites.google.com/site/testsitehacking/-7-5k-Google-services-mix-up) - Written by 🌎 [Ezequiel Pereira](sites.google.com/site/testsitehacking/).
- 🌎 [How I exploited ACME TLS-SNI-01 issuing Let's Encrypt SSL-certs for any domain using shared hosting](labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/) - Written by 🌎 [@fransrosen](twitter.com/fransrosen).
- 🌎 [TL:DR: VPN leaks users’ IPs via WebRTC. I’ve tested seventy VPN providers and 16 of them leaks users’ IPs via WebRTC (23%)](voidsec.com/vpn-leak/) - Written by 🌎 [voidsec](voidsec.com/).
- 🌎 [Escape and Evasion Egressing Restricted Networks](www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks) - Written by [Chris Patten, Tom Steele](info@optiv.com).
- 🌎 [Be careful what you copy: Invisibly inserting usernames into text with Zero-Width Characters](medium.com/@umpox/be-careful-what-you-copy-invisibly-inserting-usernames-into-text-with-zero-width-characters-18b4e6f17b66) - Written by 🌎 [@umpox](medium.com/@umpox).
- 🌎 [Domato Fuzzer's Generation Engine Internals](www.sigpwn.io/blog/2018/4/14/domato-fuzzers-generation-engine-internals) - Written by 🌎 [sigpwn](www.sigpwn.io/).
- 🌎 [CSS Is So Overpowered It Can Deanonymize Facebook Users](www.evonide.com/side-channel-attacking-browsers-through-css3-features/) - Written by 🌎 [Ruslan Habalov](www.evonide.com/).
- 🌎 [Introduction to Web Application Security](www.slideshare.net/nragupathy/introduction-to-web-application-security-blackhoodie-us-2018) - Written by 🌎 [@itsC0rg1](twitter.com/itsC0rg1), 🌎 [@jmkeads](twitter.com/jmkeads) and 🌎 [@matir](twitter.com/matir).
- 🌎 [Finding The Real Origin IPs Hiding Behind CloudFlare or TOR](www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/) - Written by 🌎 [Paul Dannewitz](www.secjuice.com/author/paul-dannewitz/).
- 🌎 [Why Facebook's api starts with a for loop](dev.to/antogarand/why-facebooks-api-starts-with-a-for-loop-1eob) - Written by 🌎 [@AntoGarand](twitter.com/AntoGarand).
- 🌎 [How I could have stolen your photos from Google - my first 3 bug bounty writeups](blog.avatao.com/How-I-could-steal-your-photos-from-Google/) - Written by 🌎 [@gergoturcsanyi](twitter.com/gergoturcsanyi).
- 🌎 [An example why NAT is NOT security](0day.work/an-example-why-nat-is-not-security/) - Written by 🌎 [@0daywork](twitter.com/@0daywork).
- 🌎 [WEB APPLICATION PENETRATION TESTING NOTES](techvomit.net/web-application-penetration-testing-notes/) - Written by 🌎 [Jayson](techvomit.net/).
- 🌎 [Hacking with a Heads Up Display](segment.com/blog/hacking-with-a-heads-up-display/) - Written by 🌎 [David Scrobonia](segment.com/blog/authors/david-scrobonia/).
- 🌎 [Alexa Top 1 Million Security - Hacking the Big Ones](slashcrypto.org/data/itsecx2018.pdf) - Written by 🌎 [@slashcrypto](twitter.com/slashcrypto).
- [The bug bounty program that changed my life](http://10degres.net/the-bug-bounty-program-that-changed-my-life/) - Written by [Gwen](http://10degres.net/).
- 🌎 [List of bug bounty writeups](pentester.land/list-of-bug-bounty-writeups.html) - Written by 🌎 [Mariem](pentester.land/).
- 🌎 [Implications of Loading .NET Assemblies](threatvector.cylance.com/en_us/home/implications-of-loading-net-assemblies.html) - Written by 🌎 [Brian Wallace](threatvector.cylance.com/en_us/contributors/brian-wallace.html).
- 🌎 [WCTF2019: Gyotaku The Flag](westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf) - Written by 🌎 [@t0nk42](twitter.com/t0nk42).
- 🌎 [How we abused Slack's TURN servers to gain access to internal services](www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise/) - Written by 🌎 [@sandrogauci](twitter.com/sandrogauci).
- 🌎 [DOS File Path Magic Tricks](medium.com/walmartlabs/dos-file-path-magic-tricks-5eda7a7a85fa) - Written by 🌎 [@clr2of8](medium.com/@clr2of8).
- 🌎 [How I got my first big bounty payout with Tesla](medium.com/heck-the-packet/how-i-got-my-first-big-bounty-payout-with-tesla-8d28b520162d) - Written by 🌎 [@cj.fairhead](medium.com/@cj.fairhead).

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, 🌎 [@qazbnm456](qazbnm456.github.io/) has waived all copyright and related or neighboring rights to this work.

## Source
<b><code>&nbsp;13105⭐</code></b> <b><code>&nbsp;&nbsp;1754🍴</code></b> [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security))
# Awesome Web Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
 🌎 [<img src="https://upload.wikimedia.org/wikipedia/commons/6/61/HTML5_logo_and_wordmark.svg" align="right" width="70">](www.w3.org/TR/html5/)

> 🐶 Curated list of Web Security materials and resources.

Needless to say, most websites suffer from various types of bugs which may eventually lead to vulnerabilities. Why would this happen so often? There can be many factors involved including misconfiguration, shortage of engineers' security skills, etc. To combat this, here is a curated list of Web Security materials and resources for learning cutting edge penetration techniques, and I highly encourage you to read this article  🌎 [So you want to be a web security researcher?](portswigger.net/blog/so-you-want-to-be-a-web-security-researcher)" first.

*Please read the [contribution guidelines](CONTRIBUTING.md) before contributing.*

---

<p align="center"><b>🌈 Want to strengthen your penetration skills?</b><br>I would recommend playing some <a href="https://github.com/apsdehal/awesome-ctf" target="_blank">awesome-ctf</a>s.</p>

---

If you enjoy this awesome list and would like to support it, check out my 🌎 [Patreon](www.patreon.com/boik) page :)<br>Also, don't forget to check out my [repos](https://github.com/qazbnm456) 🐾 or say *hi* on 🌎 [X (formerly Twitter)](x.com/boik_su)!

---

### 🤖 Using an AI assistant?

This list also ships as a Claude Code Skill so AI agents can query it at runtime — no stale snapshot, always reads the latest `data/index.json` from `master`.

**Install** (one-liner, recommended):

```bash
npx skills add qazbnm456/awesome-web-security -a claude-code -g -y
```

Or inside 🌎 [Claude Code](claude.com/claude-code), use the plugin marketplace:

```text
/plugin marketplace add qazbnm456/awesome-web-security
/plugin install awesome-web-security
```

For <b><code>&nbsp;83970⭐</code></b> <b><code>&nbsp;12190🍴</code></b> [Codex](https://github.com/openai/codex)), swap `-a claude-code` → `-a codex`.

Then ask any web-security question and the skill activates on topics like XSS, SQLi, SSRF, JWT, OAuth, recon, WAF evasion, deserialization, SAML, CTF write-ups, and more. See [`skills/awesome-web-security/SKILL.md`](skills/awesome-web-security/SKILL.md) for the full trigger list.


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
  - [Offensive](#tools-offensive)
    - [XSS](#tools-xss)
    - [SQL Injection](#tools-sql-injection)
    - [Template Injection](#tools-template-injection)
    - [XXE](#tools-xxe)
    - [CSRF](#tools-csrf)
    - [SSRF](#tools-ssrf)
  - [Leaking](#tools-leaking)
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

- 🌎 [CTF Field Guide](trailofbits.github.io/ctf/) - Written by 🌎 [Trail of Bits](www.trailofbits.com/).
- 🌎 [Hacker101](www.hacker101.com/) - Written by 🌎 [hackerone](www.hackerone.com/start-hacking).
- 🌎 [Infosec Newbie](www.sneakymonkey.net/2017/04/23/infosec-newbie/) - Written by 🌎 [Mark Robinson](www.sneakymonkey.net/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- 🌎 [The Daily Swig - Web security digest](portswigger.net/daily-swig) - Written by 🌎 [PortSwigger](portswigger.net/).
- 🌎 [The Magic of Learning](bitvijays.github.io/) - Written by 🌎 [@bitvijays](bitvijays.github.io/aboutme.html).
- 🌎 [Web Application Security Zone by Netsparker](www.netsparker.com/blog/web-security/) - Written by 🌎 [Netsparker](www.netsparker.com/).
- 🌎 [tl;dr sec](tldrsec.com/) - Weekly summary of top security tools, blog posts, and security research.

## Forums

- 🌎 [Dark Reading](www.darkreading.com/Default.asp) - Connecting The Information Security Community.
- [HackDig](http://en.hackdig.com/) - Dig high-quality web security articles for hacker.
- [Phrack Magazine](http://www.phrack.org/) - Ezine written by and for hackers.
- 🌎 [Security Weekly](securityweekly.com/) - The security podcast network.
- 🌎 [The Hacker News](thehackernews.com/) - Security in a serious way.
- [The Register](http://www.theregister.co.uk/) - Biting the hand that feeds IT.

<a name="intro"></a>
## Introduction

<a name="xss"></a>
### XSS - Cross-Site Scripting

- 🌎 [C.XSS Guide](excess-xss.com/) - Written by [@JakobKallin](https://github.com/JakobKallin) and 🌎 [Irene Lobo Valbuena](www.linkedin.com/in/irenelobovalbuena/).
- 🌎 [Cross-Site Scripting – Application Security – Google](www.google.com/intl/sw/about/appsecurity/learning/xss/) - Written by 🌎 [Google](www.google.com/).
- <b><code>&nbsp;&nbsp;2939⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;416🍴</code></b> [H5SC](https://github.com/cure53/H5SC)) - Written by [@cure53](https://github.com/cure53).
- [THE BIG BAD WOLF - XSS AND MAINTAINING ACCESS](http://www.paulosyibelo.com/2018/06/the-big-bad-wolf-xss-and-maintaining.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).
- <b><code>&nbsp;&nbsp;5106⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;779🍴</code></b> [AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)) - Written by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;55⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;135🍴</code></b> [XSS.png](https://github.com/LucaBongiorni/XSS.png)) - Written by @jackmasa.
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).
- 🌎 [Laravel Content Security Policy: Complete Implementation Guide](blog.shakiltech.com/laravel-content-security-policy-guide/) - Hands-on guide to implementing Content Security Policy in Laravel — nonce lifecycle, Vite and Livewire integration, violation reporting, and a pre-enforcement checklist, by [@itxshakil](https://github.com/itxshakil).

<a name="prototype-pollution"></a>
### Prototype Pollution

- <b><code>&nbsp;&nbsp;&nbsp;536⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88🍴</code></b> [Prototype pollution attack in NodeJS application](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)) - Written by [@HoLyVieR](https://github.com/HoLyVieR).
- 🌎 [Real-world JS - 1](blog.p6.is/Real-World-JS-1/) - Written by 🌎 [@po6ix](twitter.com/po6ix).
- 🌎 [Exploiting prototype pollution – RCE in Kibana (CVE-2019-7609)](research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/) - Written by 🌎 [@securitymb](twitter.com/securitymb).

<a name="csv-injection"></a>
### CSV Injection

- 🌎 [CSV Injection -> Meterpreter on Pornhub](news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - Written by 🌎 [Andy](blog.zsec.uk/).
- [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html) - Written by [George Mauer](http://georgemauer.net/).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - CSV Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSV%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="sql-injection"></a>
### SQL Injection

- 🌎 [SQL Injection Cheat Sheet](www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - Written by 🌎 [@netsparker](twitter.com/netsparker).
- 🌎 [SQL Injection Pocket Reference](websec.ca/kb/sql_injection) - Written by 🌎 [@LightOS](twitter.com/LightOS).
- 🌎 [SQL Injection Wiki](sqlwiki.netspi.com/) - Written by 🌎 [NETSPI](www.netspi.com/).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/sql-injection-payload-list](https://github.com/payloadbox/sql-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).

<a name="command-injection"></a>
### Command Injection

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Potential command injection in resolv.rb](https://github.com/ruby/ruby/pull/1777)) - Written by [@drigg3r](https://github.com/drigg3r).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).

<a name="orm-injection"></a>
### ORM Injection

- 🌎 [HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injection ?)](www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - Written by 🌎 [@_m0bius](twitter.com/_m0bius).
- [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by 🌎 [@h3xstream](twitter.com/h3xstream/).
- 🌎 [ORM Injection](www.slideshare.net/simone.onofri/orm-injection) - Written by 🌎 [Simone Onofri](onofri.org/).
- 🌎 [ORM2Pwn: Exploiting injections in Hibernate ORM](www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - Written by 🌎 [Mikhail Egorov](0ang3el.blogspot.tw/).

<a name="ftp-injection"></a>
### FTP Injection

- [Advisory: Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by 🌎 [Timothy Morgan](plus.google.com/105917618099766831589).
- 🌎 [SMTP over XXE − how to send emails using Java's XML parser](shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - Written by 🌎 [Alexander Klink](shiftordie.de/).

<a name="xxe"></a>
### XXE - XML eXternal Entity

- 🌎 [XXE](phonexicum.github.io/infosec/xxe.html) - Written by 🌎 [@phonexicum](twitter.com/phonexicum).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection)) - Written by various contributors.
- 🌎 [XML external entity (XXE) injection](portswigger.net/web-security/xxe) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [XML Schema, DTD, and Entity Attacks](www.vsecurity.com/download/publications/XMLDTDEntityAttacks.pdf) - Written by 🌎 [Timothy D. Morgan](twitter.com/ecbftw) and Omar Al Ibrahim.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/xxe-injection-payload-list](https://github.com/payloadbox/xxe-injection-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).

<a name="csrf"></a>
### CSRF - Cross-Site Request Forgery

- 🌎 [Wiping Out CSRF](medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - Written by 🌎 [@jrozner](medium.com/@jrozner).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - CSRF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="clickjacking"></a>
### Clickjacking

- 🌎 [Clickjacking](www.imperva.com/learn/application-security/clickjacking/) - Written by 🌎 [Imperva](www.imperva.com/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;86⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;10🍴</code></b> [X-Frame-Options: All about Clickjacking?](https://github.com/cure53/Publications/blob/master/xfo-clickjacking.pdf?raw=true)) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="ssrf"></a>
### SSRF - Server-Side Request Forgery

- 🌎 [SSRF bible. Cheatsheet](docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by 🌎 [Wallarm](wallarm.com/).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - Server-Side Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="web-cache-poisoning"></a>
### Web Cache Poisoning

- 🌎 [Practical Web Cache Poisoning](portswigger.net/blog/practical-web-cache-poisoning) - Written by 🌎 [@albinowax](twitter.com/albinowax).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - Web Cache Deception](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="relative-path-overwrite"></a>
### Relative Path Overwrite

- 🌎 [Large-scale analysis of style injection by relative path overwrite](blog.acolyer.org/2018/05/28/large-scale-analysis-of-style-injection-by-relative-path-overwrite/) - Written by 🌎 [The Morning Paper](blog.acolyer.org/).
- 🌎 [MBSD Technical Whitepaper - A few RPO exploitation techniques](www.mbsd.jp/Whitepaper/rpo.pdf) - Written by 🌎 [Mitsui Bussan Secure Directions, Inc.](www.mbsd.jp/).

<a name="open-redirect"></a>
### Open Redirect

- 🌎 [Open Redirect Vulnerability](s0cket7.com/open-redirect-vulnerability/) - Written by 🌎 [s0cket7](s0cket7.com/).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [payloadbox/open-redirect-payload-list](https://github.com/payloadbox/open-redirect-payload-list)) - Written by [@payloadbox](https://github.com/payloadbox).

<a name="saml"></a>
### Security Assertion Markup Language (SAML)

- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part I](epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part II](epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- 🌎 [How to Hunt Bugs in SAML; a Methodology - Part III](epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/) - Written by 🌎 [epi](epi052.gitlab.io/notes-to-self/).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - SAML Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SAML%20Injection)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="upload"></a>
### Upload

- 🌎 [File Upload Restrictions Bypass](www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf) - Written by 🌎 [Haboob Team](www.exploit-db.com/author/?a=9381).
- <b><code>&nbsp;77814⭐</code></b> <b><code>&nbsp;16979🍴</code></b> [PayloadsAllTheThings - Upload Insecure Files](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)) - Written by [@swisskyrepo](https://github.com/swisskyrepo).

<a name="rails"></a>
### Rails

- 🌎 [Rails Security - First part](hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).
- [Official Rails Security Guide](http://guides.rubyonrails.org/security.html) - Written by 🌎 [Rails team](rubyonrails.org/).
- 🌎 [Rails SQL Injection](rails-sqli.org) - Written by [@presidentbeef](https://github.com/presidentbeef).
- <b><code>&nbsp;&nbsp;1817⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;144🍴</code></b> [Zen Rails Security Checklist](https://github.com/brunofacca/zen-rails-security-checklist)) - Written by [@brunofacca](https://github.com/brunofacca).

<a name="angularjs"></a>
### AngularJS

- [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by 🌎 [@garethheyes](twitter.com/garethheyes).
- [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by 🌎 [Gareth Heyes](www.blogger.com/profile/10856178524811553475).

<a name="reactjs"></a>
### ReactJS

- [XSS via a spoofed React element](http://danlec.com/blog/xss-via-a-spoofed-react-element) - Written by [Daniel LeCheminant](http://danlec.com/).

<a name="ssl-tls"></a>
### SSL/TLS

- 🌎 [SSL & TLS Penetration Testing](www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by 🌎 [APTIVE](www.aptive.co.uk/).
- <b><code>&nbsp;&nbsp;&nbsp;634⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;127🍴</code></b> [Practical introduction to SSL/TLS](https://github.com/Hakky54/mutual-tls-ssl)) - Written by [@Hakky54](https://github.com/Hakky54).

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
- 🌎 [Misadventures in AWS](labs.f-secure.com/blog/misadventures-in-aws) - Written by Christian Demko.

<a name="azure"></a>
### Azure

- 🌎 [Cloud Security Risks (Part 1): Azure CSV Injection Vulnerability](rhinosecuritylabs.com/azure/cloud-security-risks-part-1-azure-csv-injection-vulnerability/) - Written by 🌎 [@spengietz](twitter.com/spengietz).
- 🌎 [Common Azure Security Vulnerabilities and Misconfigurations](rhinosecuritylabs.com/cloud-security/common-azure-security-vulnerabilities/) - Written by 🌎 [@rhinobenjamin](twitter.com/rhinobenjamin).

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

- 🌎 [Hacking with JSP Shells](blog.netspi.com/hacking-with-jsp-shells/) - Written by 🌎 [@_nullbind](twitter.com/_nullbind).
- 🌎 [Hunting for Web Shells](www.tenable.com/blog/hunting-for-web-shells) - Written by 🌎 [Jacob Baines](www.tenable.com/profile/jacob-baines).

<a name="osint"></a>
### OSINT

- 🌎 [Hacking Cryptocurrency Miners with OSINT Techniques](medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by 🌎 [@s3yfullah](medium.com/@s3yfullah).
- 🌎 [OSINT x UCCU Workshop on Open Source Intelligence](www.slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence) - Written by 🌎 [Philippe Lin](www.slideshare.net/miaoski).
- 🌎 [102 Deep Dive in the Dark Web OSINT Style Kirby Plessas](www.youtube.com/watch?v=fzd3zkAI_o4) - Presented by 🌎 [@kirbstr](twitter.com/kirbstr).
- 🌎 [The most complete guide to finding anyone’s email](www.blurbiz.io/blog/the-most-complete-guide-to-finding-anyones-email) - Written by 🌎 [Timur Daudpota](www.blurbiz.io/).

<a name="dns-rebinding"></a>
### DNS Rebinding

- 🌎 [Attacking Private Networks from the Internet with DNS Rebinding](medium.com/@brannondorsey/attacking-private-networks-from-the-internet-with-dns-rebinding-ea7098a2d325) - Written by 🌎 [@brannondorsey](medium.com/@brannondorsey).
- 🌎 [Hacking home routers from the Internet](medium.com/@radekk/hackers-can-get-access-to-your-home-router-1ddadd12a7a7) - Written by 🌎 [@radekk](medium.com/@radekk).

<a name="deserialization"></a>
### Deserialization

- 🌎 [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - Written by 🌎 [@breenmachine](twitter.com/breenmachine).
- 🌎 [.NET Roulette: Exploiting Insecure Deserialization in Telerik UI](www.youtube.com/watch?v=--6PiuvBGAU) - Written by 🌎 [@noperator](twitter.com/noperator).
- 🌎 [Attacking .NET deserialization](www.youtube.com/watch?v=eDfGpu3iE4Q) - Written by 🌎 [@pwntester](twitter.com/pwntester).
- 🌎 [How to exploit the DotNetNuke Cookie Deserialization](pentest-tools.com/blog/exploit-dotnetnuke-cookie-deserialization/) - Written by 🌎 [CRISTIAN CORNEA](pentest-tools.com/blog/author/pentest-cristian/).
- 🌎 [HOW TO EXPLOIT LIFERAY CVE-2020-7961 : QUICK JOURNEY TO POC](www.synacktiv.com/en/publications/how-to-exploit-liferay-cve-2020-7961-quick-journey-to-poc.html) - Written by 🌎 [@synacktiv](twitter.com/synacktiv).

<a name="oauth"></a>
### OAuth

- 🌎 [What is going on with OAuth 2.0? And why you should not use it for authentication.](medium.com/securing/what-is-going-on-with-oauth-2-0-and-why-you-should-not-use-it-for-authentication-5f47597b2611) - Written by 🌎 [@damianrusinek](medium.com/@damianrusinek).
- 🌎 [Introduction to OAuth 2.0 and OpenID Connect](pragmaticwebsecurity.com/courses/introduction-oauth-oidc.html) - Written by 🌎 [@PhilippeDeRyck](twitter.com/PhilippeDeRyck).

<a name="jwt"></a>
### JWT

- 🌎 [Hardcoded secrets, unverified tokens, and other common JWT mistakes](r2c.dev/blog/2020/hardcoded-secrets-unverified-tokens-and-other-common-jwt-mistakes/) - Written by 🌎 [@ermil0v](twitter.com/ermil0v).

## Evasions

<a name="evasions-xxe"></a>
### XXE

- 🌎 [Bypass Fix of OOB XXE Using Different encoding](twitter.com/SpiderSec/status/1191375472690528256) - Written by 🌎 [@SpiderSec](twitter.com/SpiderSec).

<a name="evasions-csp"></a>
### CSP

- 🌎 [CSP: bypassing form-action with reflected XSS](labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - Written by 🌎 [Detectify Labs](labs.detectify.com/).
- [TWITTER XSS + CSP BYPASS](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).
- 🌎 [Neatly bypassing CSP](lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa) - Written by 🌎 [Wallarm](wallarm.com/).
- 🌎 [Evading CSP with DOM-based dangling markup](portswigger.net/blog/evading-csp-with-dom-based-dangling-markup) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [GitHub's CSP journey](githubengineering.com/githubs-csp-journey/) - Written by [@ptoomey3](https://github.com/ptoomey3).
- 🌎 [GitHub's post-CSP journey](githubengineering.com/githubs-post-csp-journey/) - Written by [@ptoomey3](https://github.com/ptoomey3).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Any protection against dynamic module import?](https://github.com/w3c/webappsec-csp/issues/243)) - Written by 🌎 [@shhnjk](twitter.com/@shhnjk).

<a name="evasions-waf"></a>
### WAF

- 🌎 [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - Written by 🌎 [@Brett Buerhaus](twitter.com/bbuerhaus).
- 🌎 [How to bypass libinjection in many WAF/NGWAF](medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f) - Written by 🌎 [@d0znpp](medium.com/@d0znpp).
- 🌎 [Web Application Firewall (WAF) Evasion Techniques](medium.com/secjuice/waf-evasion-techniques-718026d693d8) - Written by 🌎 [@secjuice](twitter.com/secjuice).
- 🌎 [Web Application Firewall (WAF) Evasion Techniques #2](medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - Written by 🌎 [@secjuice](twitter.com/secjuice).

<a name="evasions-jsmvc"></a>
### JSMVC

- [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

<a name="evasions-authentication"></a>
### Authentication

- [Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - Written by 🌎 [@malerisch](twitter.com/malerisch) and 🌎 [@steventseeley](twitter.com/steventseeley).

## Tricks

<a name="tricks-csrf"></a>
### CSRF

- 🌎 [Exploiting CSRF on JSON endpoints with Flash and redirects](blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b) - Written by 🌎 [@riyazwalikar](blog.appsecco.com/@riyazwalikar).
- 🌎 [Neat tricks to bypass CSRF-protection](zhuanlan.zhihu.com/p/32716181) - Written by 🌎 [Twosecurity](twosecurity.io/).
- <b><code>&nbsp;&nbsp;&nbsp;324⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;49🍴</code></b> [Stealing CSRF tokens with CSS injection (without iFrames)](https://github.com/dxa4481/cssInjection)) - Written by [@dxa4481](https://github.com/dxa4481).
- 🌎 [Cracking Java’s RNG for CSRF - Javax Faces and Why CSRF Token Randomness Matters](blog.securityevaluators.com/cracking-javas-rng-for-csrf-ea9cacd231d2) - Written by 🌎 [@rramgattie](blog.securityevaluators.com/@rramgattie).
- 🌎 [If HttpOnly You Could Still CSRF… Of CORS you can!](medium.com/@_graphx/if-httponly-you-could-still-csrf-of-cors-you-can-5d7ee2c7443) - Written by 🌎 [@GraphX](twitter.com/GraphX).

<a name="tricks-clickjacking"></a>
### Clickjacking

- 🌎 [Clickjackings in Google worth 14981.7$](medium.com/@raushanraj_65039/google-clickjacking-6a04132b918a) - Written by 🌎 [@raushanraj_65039](medium.com/@raushanraj_65039).

<a name="tricks-rce"></a>
### Remote Code Execution

- 🌎 [DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE](www.ambionics.io/blog/drupal-services-module-rce) - Written by 🌎 [Ambionics Security](www.ambionics.io/).
- 🌎 [Exploiting Node.js deserialization bug for Remote Code Execution](opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - Written by 🌎 [OpSecX](opsecx.com/index.php/author/ajinabraham/).
- [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
- 🌎 [How we exploited a remote code execution vulnerability in math.js](capacitorset.github.io/mathjs/) - Written by [@capacitorset](https://github.com/capacitorset).
- 🌎 [$36k Google App Engine RCE](sites.google.com/site/testsitehacking/-36k-google-app-engine-rce) - Written by 🌎 [Ezequiel Pereira](sites.google.com/site/testsitehacking/).
- 🌎 [Poor RichFaces](codewhitesec.blogspot.com/2018/05/poor-richfaces.html) - Written by 🌎 [CODE WHITE](www.code-white.com/).
- 🌎 [Remote Code Execution on a Facebook server](blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) - Written by 🌎 [@blaklis_](twitter.com/blaklis_).
- 🌎 [Evil Teacher: Code Injection in Moodle](blog.ripstech.com/2018/moodle-remote-code-execution/) - Written by 🌎 [RIPS Technologies](www.ripstech.com/).
- 🌎 [WebLogic RCE (CVE-2019-2725) Debug Diary](paper.seebug.org/910/) - Written by Badcode@Knownsec 404 Team.
- 🌎 [What Do WebLogic, WebSphere, JBoss, Jenkins, OpenNMS, and Your Application Have in Common? This Vulnerability.](foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/) - Written by 🌎 [@breenmachine](twitter.com/@breenmachine).
- 🌎 [CVE-2019-1306: ARE YOU MY INDEX?](www.thezdi.com/blog/2019/10/23/cve-2019-1306-are-you-my-index) - Written by 🌎 [@yu5k3](twitter.com/yu5k3).

<a name="tricks-xss"></a>
### XSS

- 🌎 [DON'T TRUST THE DOM: BYPASSING XSS MITIGATIONS VIA SCRIPT GADGETS](www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - Written by 🌎 [Sebastian Lekies](twitter.com/slekies), 🌎 [Krzysztof Kotowicz](twitter.com/kkotowicz), and 🌎 [Eduardo Vela](twitter.com/sirdarckcat).
- [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).
- 🌎 [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.u50nrzhas) - Written by 🌎 [@marin_m](medium.com/@marin_m).
- 🌎 [Query parameter reordering causes redirect page to render unsafe URL](hackerone.com/reports/293689) - Written by 🌎 [kenziy](hackerone.com/kenziy).
- [Uber XSS via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - Written by [zhchbin](http://zhchbin.github.io/).
- 🌎 [Stored XSS on Facebook](opnsec.com/2018/03/stored-xss-on-facebook/) - Written by 🌎 [Enguerran Gillier](opnsec.com/).
- [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth14.html) - Written by [StamOne_](http://stamone-bug-bounty.blogspot.tw/).
- 🌎 [Another XSS in Google Colaboratory](blog.bentkowski.info/2018/09/another-xss-in-google-colaboratory.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [XSS in Google Colaboratory + CSP bypass](blog.bentkowski.info/2018/06/xss-in-google-colaboratory-csp-bypass.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [</script> is filtered ?](twitter.com/strukt93/status/931586377665331200) - Written by 🌎 [@strukt93](twitter.com/strukt93).
- 🌎 [XSS-Auditor — the protector of unprotected and the deceiver of protected.](medium.com/bugbountywriteup/xss-auditor-the-protector-of-unprotected-f900a5e15b7b) - Written by 🌎 [@terjanq](medium.com/@terjanq).
- 🌎 [XSS without parentheses and semi-colons](portswigger.net/blog/xss-without-parentheses-and-semi-colons) - Written by 🌎 [@garethheyes](twitter.com/garethheyes).
- 🌎 [Upgrade self XSS to Exploitable XSS an 3 Ways Technic](www.hahwul.com/2019/11/upgrade-self-xss-to-exploitable-xss.html) - Written by 🌎 [HAHWUL](www.hahwul.com/).
- 🌎 [Exploiting XSS with 20 characters limitation](jlajara.gitlab.io/posts/2019/11/30/XSS_20_characters.html) - Written by 🌎 [Jorge Lajara](jlajara.gitlab.io/).
- 🌎 [$20000 Facebook DOM XSS](vinothkumar.me/20000-facebook-dom-xss/) - Written by 🌎 [@vinodsparrow](twitter.com/vinodsparrow).

<a name="tricks-sql-injection"></a>
### SQL Injection

- [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - Written by [Orange](http://blog.orange.tw/).
- [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - Written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).
- 🌎 [Making a Blind SQL Injection a little less blind](medium.com/@tomnomnom/making-a-blind-sql-injection-a-little-less-blind-428dcb614ba8) - Written by 🌎 [TomNomNom](twitter.com/TomNomNom).
- 🌎 [Red Team Tales 0x01: From MSSQL to RCE](www.tarlogic.com/en/blog/red-team-tales-0x01/) - Written by 🌎 [Tarlogic](www.tarlogic.com/en/cybersecurity-blog/).
- 🌎 [MySQL Error Based SQL Injection Using EXP](www.exploit-db.com/docs/english/37953-mysql-error-based-sql-injection-using-exp.pdf) - Written by 🌎 [@osandamalith](twitter.com/osandamalith).
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
- 🌎 [Automating local DTD discovery for XXE exploitation](www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation) - Written by 🌎 [Philippe Arteau](twitter.com/h3xstream).
- 🌎 [Exploiting XXE with local DTD files](mohemiv.com/all/exploiting-xxe-with-local-dtd-files/) - Written by 🌎 [Arseniy Sharoglazov](twitter.com/_mohemiv).
- 🌎 [Forcing XXE Reflection through Server Error Messages](blog.netspi.com/forcing-xxe-reflection-server-error-messages/) - Written by 🌎 [Antti Rantasaari](blog.netspi.com/author/antti-rantasaari/).
- 🌎 [Pre-authentication XXE vulnerability in the Services Drupal module](www.synacktiv.com/ressources/synacktiv_drupal_xxe_services.pdf) - Written by 🌎 [Renaud Dubourguais](twitter.com/_m0bius).
- 🌎 [What You Didn't Know About XML External Entities Attacks](2013.appsecusa.org/2013/wp-content/uploads/2013/12/WhatYouDidntKnowAboutXXEAttacks.pdf) - Written by 🌎 [Timothy D. Morgan](twitter.com/ecbftw).
- 🌎 [XML Out-Of-Band Data Retrieval](media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by Timur Yunusov and Alexey Osipov.
- [XXE in WeChat Pay Sdk ( WeChat leave a backdoor on merchant websites)](http://seclists.org/fulldisclosure/2018/Jul/3) - Written by 🌎 [Rose Jackcode](twitter.com/codeshtool).
- [XXE OOB exploitation at Java 1.7+ (2014)](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - Exfiltration using FTP protocol - Written by 🌎 [Ivan Novikov](twitter.com/d0znpp/).
- 🌎 [XXE OOB extracting via HTTP+FTP using single opened port](skavans.ru/en/2017/12/02/xxe-oob-extracting-via-httpftp-using-single-opened-port/) - Written by 🌎 [skavans](skavans.ru/).

<a name="tricks-ssrf"></a>
### SSRF

- 🌎 [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - Written by [Orange](http://blog.orange.tw/).
- 🌎 [SSRF in https://imgur.com/vidgif/url](hackerone.com/reports/115748) - Written by 🌎 [aesteral](hackerone.com/aesteral).
- [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - Written by [xl7dev](http://blog.safebuff.com/).
- 🌎 [PHP SSRF Techniques](medium.com/secjuice/php-ssrf-techniques-9d422cb28d51) - Written by 🌎 [@themiddleblue](medium.com/@themiddleblue).
- 🌎 [SSRF in Exchange leads to ROOT access in all instances](hackerone.com/reports/341876) - Written by 🌎 [@0xacb](twitter.com/0xacb).
- 🌎 [Into the Borg – SSRF inside Google production network](opnsec.com/2018/07/into-the-borg-ssrf-inside-google-production-network/) - Written by 🌎 [opnsec](opnsec.com/).
- 🌎 [Piercing the Veil: Server Side Request Forgery to NIPRNet access](medium.com/bugbountywriteup/piercing-the-veil-server-side-request-forgery-to-niprnet-access-c358fd5e249a) - Written by 🌎 [Alyssa Herrera](medium.com/@alyssa.o.herrera).
- 🌎 [All you need to know about SSRF and how may we write tools to do auto-detect](www.auxy.xyz/web%20security/2017/07/06/all-ssrf-knowledge.html) - Written by 🌎 [@Auxy233](twitter.com/Auxy233).
- [AWS takeover through SSRF in JavaScript](http://10degres.net/aws-takeover-through-ssrf-in-javascript/) - Written by [Gwen](http://10degres.net/).

<a name="tricks-web-cache-poisoning"></a>
### Web Cache Poisoning

- 🌎 [Bypassing Web Cache Poisoning Countermeasures](portswigger.net/blog/bypassing-web-cache-poisoning-countermeasures) - Written by 🌎 [@albinowax](twitter.com/albinowax).
- 🌎 [Cache poisoning and other dirty tricks](lab.wallarm.com/cache-poisoning-and-other-dirty-tricks-120468f1053f) - Written by 🌎 [Wallarm](wallarm.com/).

<a name="tricks-header-injection"></a>
### Header Injection

- [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by 🌎 [Timothy Morgan](plus.google.com/105917618099766831589).

<a name="tricks-url"></a>
### URL

- [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - Written by [Sergey Bobrov](http://blog.blackfan.ru/).
- 🌎 [Phishing with Unicode Domains](www.xudongz.com/blog/2017/idn-phishing/) - Written by 🌎 [Xudong Zheng](www.xudongz.com/).
- 🌎 [Some Problems Of URLs](noncombatant.org/2017/11/07/problems-of-urls/) - Written by 🌎 [Chris Palmer](noncombatant.org/about/).
- 🌎 [Unicode Domains are bad and you should feel bad for supporting them](www.vgrsec.com/post20170219.html) - Written by 🌎 [VRGSEC](www.vgrsec.com/).

<a name="tricks-deserialization"></a>
### Deserialization

- 🌎 [ASP.NET resource files (.RESX) and deserialisation issues](www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/august/aspnet-resource-files-resx-and-deserialisation-issues/) - Written by 🌎 [@irsdl](twitter.com/irsdl).

<a name="tricks-oauth"></a>
### OAuth

- 🌎 [Facebook OAuth Framework Vulnerability](www.amolbaikar.com/facebook-oauth-framework-vulnerability/) - Written by 🌎 [@AmolBaikar](twitter.com/AmolBaikar).

<a name="tricks-others"></a>
### Others

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;41⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [Inducing DNS Leaks in Onion Web Services](https://github.com/epidemics-scepticism/writing/blob/master/onion-dns-leaks.md)) - Written by [@epidemics-scepticism](https://github.com/epidemics-scepticism).
- 🌎 [Stored XSS, and SSRF in Google using the Dataset Publishing Language](s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html) - Written by 🌎 [@signalchaos](twitter.com/signalchaos).
- 🌎 [How I hacked Google’s bug tracking system itself for $15,600 in bounties](medium.com/free-code-camp/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5) - Written by 🌎 [@alex.birsan](medium.com/@alex.birsan).
- 🌎 [Some Tricks From My Secret Group](www.leavesongs.com/SHARE/some-tricks-from-my-secret-group.html) - Written by 🌎 [phithon](www.leavesongs.com/).

## Browser Exploitation

### Frontend (like SOP bypass, URL spoofing, and something like that)

- 🌎 [IE11 Information disclosure - local file detection](www.facebook.com/ExploitWareLabs/photos/a.361854183878462.84544.338832389513975/1378579648872572/?type=3&theater) - Written by James Lee.
- [JSON hijacking for the modern web](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html) - Written by 🌎 [portswigger](portswigger.net/).
- 🌎 [SOP bypass / UXSS – Stealing Credentials Pretty Fast (Edge)](www.brokenbrowser.com/sop-bypass-uxss-stealing-credentials-pretty-fast/) - Written by 🌎 [Manuel](twitter.com/magicmac2000).
- 🌎 [Особенности Safari в client-side атаках](bo0om.ru/safari-client-side) - Written by 🌎 [Bo0oM](bo0om.ru/author/admin).
- 🌎 [How do we Stop Spilling the Beans Across Origins?](docs.google.com/document/d/1cbL-X0kV_tQ5rL8XJ3lXkV-j0pt_CfTu5ZSzYrncPDc/) - Written by [aaj at google.com](mailto:aaj@google.com) and [mkwst at google.com](mailto:mkwst@google.com).
- 🌎 [Setting arbitrary request headers in Chromium via CRLF injection](blog.bentkowski.info/2018/06/setting-arbitrary-request-headers-in.html) - Written by 🌎 [Michał Bentkowski](blog.bentkowski.info/).
- 🌎 [I’m harvesting credit card numbers and passwords from your site. Here’s how.](hackernoon.com/im-harvesting-credit-card-numbers-and-passwords-from-your-site-here-s-how-9a8cb347c5b5) - Written by 🌎 [David Gilbertson](hackernoon.com/@david.gilbertson).
- 🌎 [The inception bar: a new phishing method](jameshfisher.com/2019/04/27/the-inception-bar-a-new-phishing-method/) - Written by 🌎 [jameshfisher](jameshfisher.com/).
- 🌎 [Bypassing Mobile Browser Security For Fun And Profit](www.blackhat.com/docs/asia-16/materials/asia-16-Baloch-Bypassing-Browser-Security-Policies-For-Fun-And-Profit-wp.pdf) - Written by 🌎 [@rafaybaloch](twitter.com/@rafaybaloch).
- 🌎 [The Cookie Monster in Your Browsers](speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers) - Written by 🌎 [@filedescriptor](twitter.com/filedescriptor).
- 🌎 [The world of Site Isolation and compromised renderer](speakerdeck.com/shhnjk/the-world-of-site-isolation-and-compromised-renderer) - Written by 🌎 [@shhnjk](twitter.com/shhnjk).
- 🌎 [Sending arbitrary IPC messages via overriding Function.prototype.apply](hackerone.com/reports/188086) - Written by 🌎 [@kinugawamasato](twitter.com/kinugawamasato).
- 🌎 [Take Advantage of Out-of-Scope Domains in Bug Bounty Programs](ahussam.me/Take-Advantage-of-Out-of-Scope-Domains-in-Bug-Bounty/) - Written by 🌎 [@Abdulahhusam](twitter.com/Abdulahhusam).

### Backend (core of Browser implementation, and often refers to C or C++ part)

- [Attacking JavaScript Engines - A case study of JavaScriptCore and CVE-2016-4622](http://www.phrack.org/papers/attacking_javascript_engines.html) - Written by [phrack@saelo.net](mailto:phrack@saelo.net).
- 🌎 [Exploiting a V8 OOB write.](halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/) - Written by 🌎 [@halbecaf](twitter.com/halbecaf).
- 🌎 [SSD Advisory – Chrome Turbofan Remote Code Execution](blogs.securiteam.com/index.php/archives/3379) - Written by 🌎 [SecuriTeam Secure Disclosure (SSD)](blogs.securiteam.com/).
- 🌎 [Look Mom, I don't use Shellcode - Browser Exploitation Case Study for Internet Explorer 11](labs.bluefrostsecurity.de/files/Look_Mom_I_Dont_Use_Shellcode-WP.pdf) - Written by [@moritzj](http://twitter.com/moritzj).
- 🌎 [PUSHING WEBKIT'S BUTTONS WITH A MOBILE PWN2OWN EXPLOIT](www.zerodayinitiative.com/blog/2018/2/12/pushing-webkits-buttons-with-a-mobile-pwn2own-exploit) - Written by 🌎 [@wanderingglitch](twitter.com/wanderingglitch).
- 🌎 [A Methodical Approach to Browser Exploitation](blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/) - Written by 🌎 [RET2 SYSTEMS, INC](blog.ret2.io/).
- 🌎 [CVE-2017-2446 or JSC::JSGlobalObject::isHavingABadTime.](doar-e.github.io/blog/2018/07/14/cve-2017-2446-or-jscjsglobalobjectishavingabadtime/) - Written by 🌎 [Diary of a reverse-engineer](doar-e.github.io/).
- 🌎 [Breaking UC Browser](habr.com/en/company/drweb/blog/452076/) - Written by 🌎 [Доктор Веб](www.drweb.ru/).
- [Three roads lead to Rome](http://blogs.360.cn/360safe/2016/11/29/three-roads-lead-to-rome-2/) - Written by 🌎 [@holynop](twitter.com/holynop).
- 🌎 [CLEANLY ESCAPING THE CHROME SANDBOX](theori.io/research/escaping-chrome-sandbox) - Written by 🌎 [@tjbecker_](twitter.com/tjbecker_).

## PoCs

<a name="pocs-database"></a>
### Database

- <b><code>&nbsp;&nbsp;3503⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;722🍴</code></b> [awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc)) - Curated list of CVE PoCs by [@qazbnm456](https://github.com/qazbnm456).
- <b><code>&nbsp;&nbsp;2318⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;404🍴</code></b> [js-vuln-db](https://github.com/tunz/js-vuln-db)) - Collection of JavaScript engine CVEs with PoCs by [@tunz](https://github.com/tunz).
- <b><code>&nbsp;&nbsp;2497⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;967🍴</code></b> [Some-PoC-oR-ExP](https://github.com/coffeehb/Some-PoC-oR-ExP)) - 各种漏洞poc、Exp的收集或编写 by [@coffeehb](https://github.com/coffeehb).
- <b><code>&nbsp;&nbsp;&nbsp;701⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;83🍴</code></b> [uxss-db](https://github.com/Metnew/uxss-db)) - Collection of UXSS CVEs with PoCs by [@Metnew](https://github.com/Metnew).
- 🌎 [SPLOITUS](sploitus.com/) - Exploits & Tools Search Engine by 🌎 [@i_bo0om](twitter.com/i_bo0om).
- 🌎 [Exploit Database](www.exploit-db.com/) - ultimate archive of Exploits, Shellcode, and Security Papers by 🌎 [Offensive Security](www.offensive-security.com/).

## Cheetsheets

- <b><code>&nbsp;&nbsp;&nbsp;136⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;12🍴</code></b> [Capture the Flag CheatSheet](https://github.com/uppusaikiran/awesome-ctf-cheatsheet)) - Written by [@uppusaikiran](https://github.com/uppusaikiran).
- 🌎 [XSS Cheat Sheet - 2018 Edition](leanpub.com/xss) - Written by 🌎 [@brutelogic](twitter.com/brutelogic).

## Tools

<a name="tools-auditing"></a>
### Auditing

- <b><code>&nbsp;&nbsp;&nbsp;634⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;169🍴</code></b> [A2SV](https://github.com/hahwul/a2sv)) - Auto Scanning to SSL Vulnerability by [@hahwul](https://github.com/hahwul).
- <b><code>&nbsp;13846⭐</code></b> <b><code>&nbsp;&nbsp;2139🍴</code></b> [prowler](https://github.com/Alfresco/prowler)) - Tool for AWS security assessment, auditing and hardening by [@Alfresco](https://github.com/Alfresco).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [slurp](https://github.com/hehnope/slurp)) - Evaluate the security of S3 buckets by [@hehnope](https://github.com/hehnope).

<a name="tools-command-injection"></a>
### Command Injection

- <b><code>&nbsp;&nbsp;5740⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;929🍴</code></b> [commix](https://github.com/commixproject/commix)) - Automated All-in-One OS command injection and exploitation tool by [@commixproject](https://github.com/commixproject).

<a name="tools-reconnaissance"></a>
### Reconnaissance

<a name="tools-osint"></a>
#### OSINT - Open-Source Intelligence

- 🌎 [Censys](censys.io/) - Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet by 🌎 [University of Michigan](umich.edu/).
- <b><code>&nbsp;&nbsp;3537⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;623🍴</code></b> [FOCA](https://github.com/ElevenPaths/FOCA)) - FOCA (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans by 🌎 [ElevenPaths](www.elevenpaths.com/index.html).
- 🌎 [FOFA](fofa.so/?locale=en) - Cyberspace Search Engine by [BAIMAOHUI](http://baimaohui.net/).
- <b><code>&nbsp;&nbsp;6175⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;844🍴</code></b> [gitrob](https://github.com/michenriksen/Gitrob)) - Reconnaissance tool for GitHub organizations by [@michenriksen](https://github.com/michenriksen).
- <b><code>&nbsp;&nbsp;2147⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;484🍴</code></b> [GSIL](https://github.com/FeeiCN/GSIL)) - Github Sensitive Information Leakage（Github敏感信息泄露）by [@FeeiCN](https://github.com/FeeiCN).
- 🌎 [NSFOCUS](nti.nsfocus.com/) - THREAT INTELLIGENCE PORTAL by NSFOCUS GLOBAL.
- <b><code>&nbsp;&nbsp;&nbsp;797⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;162🍴</code></b> [raven](https://github.com/0x09AL/raven)) - raven is a Linkedin information gathering tool that can be used by pentesters to gather information about an organization employees using Linkedin by [@0x09AL](https://github.com/0x09AL).
- 🌎 [Shodan](www.shodan.io/) - Shodan is the world's first search engine for Internet-connected devices by 🌎 [@shodanhq](twitter.com/shodanhq).
- [SpiderFoot](http://www.spiderfoot.net/) - Open source footprinting and intelligence-gathering tool by 🌎 [@binarypool](twitter.com/binarypool).
- 🌎 [urlscan.io](urlscan.io/) - Service which analyses websites and the resources they request by 🌎 [@heipei](twitter.com/heipei).
- <b><code>&nbsp;&nbsp;2309⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;298🍴</code></b> [xray](https://github.com/evilsocket/xray)) - XRay is a tool for recon, mapping and OSINT gathering from public networks by [@evilsocket](https://github.com/evilsocket).
- 🌎 [ZoomEye](www.zoomeye.org/) - Cyberspace Search Engine by 🌎 [@zoomeye_team](twitter.com/zoomeye_team).
- 🌎 [Databases - start.me](start.me/p/QRENnO/databases) - Various databases which you can use for your OSINT research by 🌎 [@technisette](twitter.com/technisette).
- 🌎 [peoplefindThor](peoplefindthor.dk/) - the easy way to find people on Facebook by [postkassen](mailto:postkassen@oejvind.dk?subject=peoplefindthor.dk%20comments).
- <b><code>&nbsp;&nbsp;1974⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;266🍴</code></b> [tinfoleak](https://github.com/vaguileradiaz/tinfoleak)) - The most complete open-source tool for Twitter intelligence analysis by [@vaguileradiaz](https://github.com/vaguileradiaz).
- <b><code>&nbsp;12889⭐</code></b> <b><code>&nbsp;&nbsp;1674🍴</code></b> [Photon](https://github.com/s0md3v/Photon)) - Incredibly fast crawler designed for OSINT by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;2049⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;357🍴</code></b> [ReconDog](https://github.com/s0md3v/ReconDog)) - Reconnaissance Swiss Army Knife by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;40⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [espi0n/Dockerfiles](https://github.com/espi0n/Dockerfiles)) - Dockerfiles for various OSINT tools by [@espi0n](https://github.com/espi0n).
- <b><code>&nbsp;&nbsp;3555⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;441🍴</code></b> [Raccoon](https://github.com/evyatarmeged/Raccoon)) - High performance offensive security tool for reconnaissance and vulnerability scanning by [@evyatarmeged](https://github.com/evyatarmeged).
- <b><code>&nbsp;&nbsp;4026⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;817🍴</code></b> [Social Mapper](https://github.com/SpiderLabs/social_mapper)) - Social Media Enumeration & Correlation Tool by Jacob Wilkin(Greenwolf) by [@SpiderLabs](https://github.com/SpiderLabs).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [Marshall Extensions](https://github.com/bad-antics/marshall-extensions)) - OSINT and security extensions for the Marshall privacy browser, providing reconnaissance and security-testing plugins by [@bad-antics](https://github.com/bad-antics).
- 🌎 [OpenBuckets](openbuckets.io/) - Search engine for misconfigured public cloud storage buckets across any provider.

<a name="tools-sub-domain-enumeration"></a>
#### Sub Domain Enumeration

- <b><code>&nbsp;&nbsp;5937⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;906🍴</code></b> [AQUATONE](https://github.com/michenriksen/aquatone)) - Tool for Domain Flyovers by [@michenriksen](https://github.com/michenriksen).
- 🌎 [Certificate Search](crt.sh/) - Enter an Identity (Domain Name, Organization Name, etc), a Certificate Fingerprint (SHA-1 or SHA-256) or a crt.sh ID to search certificate(s) by [@crtsh](https://github.com/crtsh).
- <b><code>&nbsp;&nbsp;&nbsp;887⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;289🍴</code></b> [Certificate Transparency](https://github.com/google/certificate-transparency)) - Google's Certificate Transparency project fixes several structural flaws in the SSL certificate system by [@google](https://github.com/google).
- <b><code>&nbsp;&nbsp;1865⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;237🍴</code></b> [domain_analyzer](https://github.com/eldraco/domain_analyzer)) - Analyze the security of any domain by finding all the information possible by [@eldraco](https://github.com/eldraco).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;62⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5🍴</code></b> [EyeWitness](https://github.com/ChrisTruncer/EyeWitness)) - EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible by [@ChrisTruncer](https://github.com/ChrisTruncer).
- <b><code>&nbsp;&nbsp;&nbsp;184⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;52🍴</code></b> [GSDF](https://github.com/We5ter/GSDF)) - Domain searcher named GoogleSSLdomainFinder by [@We5ter](https://github.com/We5ter).
- <b><code>&nbsp;&nbsp;3611⭐</code></b> <b><code>&nbsp;&nbsp;1007🍴</code></b> [subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)) - A simple and fast sub domain brute tool for pentesters by [@lijiejie](https://github.com/lijiejie).
- 🌎 [VirusTotal domain information](www.virustotal.com/en/documentation/searching/#getting-domain-information) - Searching for domain information by 🌎 [VirusTotal](www.virustotal.com/).
- <b><code>&nbsp;10932⭐</code></b> <b><code>&nbsp;&nbsp;2207🍴</code></b> [Sublist3r](https://github.com/aboul3la/Sublist3r)) - Sublist3r is a multi-threaded sub-domain enumeration tool for penetration testers by [@aboul3la](https://github.com/aboul3la).

<a name="tools-code-generating"></a>
### Code Generating

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;85⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;16🍴</code></b> [VWGen](https://github.com/qazbnm456/VWGen)) - Vulnerable Web applications Generator by [@qazbnm456](https://github.com/qazbnm456).

<a name="tools-fuzzing"></a>
### Fuzzing

- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [charsetinspect](https://github.com/hack-all-the-things/charsetinspect)) - Script that inspects multi-byte character sets looking for characters with specific user-defined properties by [@hack-all-the-things](https://github.com/hack-all-the-things).
- <b><code>&nbsp;&nbsp;&nbsp;146⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;45🍴</code></b> [IPObfuscator](https://github.com/OsandaMalith/IPObfuscator)) - Simple tool to convert the IP to a DWORD IP by [@OsandaMalith](https://github.com/OsandaMalith).
- <b><code>&nbsp;&nbsp;6491⭐</code></b> <b><code>&nbsp;&nbsp;1402🍴</code></b> [wfuzz](https://github.com/xmendez/wfuzz)) - Web application bruteforcer by [@xmendez](https://github.com/xmendez).
- <b><code>&nbsp;&nbsp;1778⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;284🍴</code></b> [domato](https://github.com/google/domato)) - DOM fuzzer by [@google](https://github.com/google).
- <b><code>&nbsp;&nbsp;8906⭐</code></b> <b><code>&nbsp;&nbsp;2114🍴</code></b> [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
- <b><code>&nbsp;&nbsp;1997⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;269🍴</code></b> [dirhunt](https://github.com/Nekmo/dirhunt)) - Web crawler optimized for searching and analyzing the directory structure of a site by [@nekmo](https://github.com/Nekmo).
- 🌎 [ssltest](www.ssllabs.com/ssltest/) - Online service that performs a deep analysis of the configuration of any SSL web server on the public internet. Provided by 🌎 [Qualys SSL Labs](www.ssllabs.com).
- <b><code>&nbsp;&nbsp;3306⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;529🍴</code></b> [fuzz.txt](https://github.com/Bo0oM/fuzz.txt)) - Potentially dangerous files by [@Bo0oM](https://github.com/Bo0oM).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [wayparam](https://github.com/aleff-github/wayparam)) - Cross-platform Python CLI that fetches historical URLs from the Wayback CDX API and outputs normalized parameterized URLs for fuzzing, by [@aleff-github](https://github.com/aleff-github).

<a name="tools-scanning"></a>
### Scanning

- <b><code>&nbsp;&nbsp;&nbsp;257⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;72🍴</code></b> [JoomlaScan](https://github.com/drego85/JoomlaScan)) - Free software to find the components installed in Joomla CMS, built out of the ashes of Joomscan by [@drego85](https://github.com/drego85).
- <b><code>&nbsp;&nbsp;9580⭐</code></b> <b><code>&nbsp;&nbsp;1341🍴</code></b> [wpscan](https://github.com/wpscanteam/wpscan)) - WPScan is a black box WordPress vulnerability scanner by [@wpscanteam](https://github.com/wpscanteam).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [WAScan](https://github.com/m4ll0k/WAScan)) - Is an open source web application security scanner that uses "black-box" method, created by [@m4ll0k](https://github.com/m4ll0k).
- <b><code>&nbsp;28765⭐</code></b> <b><code>&nbsp;&nbsp;3431🍴</code></b> [Nuclei](https://github.com/projectdiscovery/nuclei)) - Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use by [@projectdiscovery](https://github.com/projectdiscovery).
- 🌎 [ZAP by Checkmarx](zaproxy.org) - Open-source web application security scanner maintained by the ZAP Core Team.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Fray](https://github.com/dalisecurity/fray)) - Open-source WAF bypass and security-testing toolkit with 6,300+ payloads across OWASP categories, AI-assisted evasion engine, 27-check reconnaissance pipeline, and OWASP hardening audit, by [@dalisecurity](https://github.com/dalisecurity).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [Trust Scan](https://github.com/undeadlist/trust-scan)) - URL security scanner combining threat intelligence (URLhaus, PhishTank, Spamhaus) with 40+ scam and phishing pattern detection by [@undeadlist](https://github.com/undeadlist).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [ZeroTrust](https://github.com/sattyamjjain/zerotrust)) - Privacy-first Chrome extension that analyzes website security locally with on-device AI (WebGPU), producing trust scores from HTTPS, phishing, malicious-script, and cookie-compliance signals, by [@sattyamjjain](https://github.com/sattyamjjain).

<a name="tools-penetration-testing"></a>
### Penetration Testing

- 🌎 [Burp Suite](portswigger.net/burp/) - Burp Suite is an integrated platform for performing security testing of web applications by 🌎 [portswigger](portswigger.net/).
- <b><code>&nbsp;&nbsp;2647⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;413🍴</code></b> [Astra](https://github.com/flipkart-incubator/astra)) - Automated Security Testing For REST API's by [@flipkart-incubator](https://github.com/flipkart-incubator).
- <b><code>&nbsp;&nbsp;1224⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;193🍴</code></b> [aws_pwn](https://github.com/dagrz/aws_pwn)) - A collection of AWS penetration testing junk by [@dagrz](https://github.com/dagrz).
- 🌎 [grayhatwarfare](buckets.grayhatwarfare.com/) - Public buckets by [grayhatwarfare](http://www.grayhatwarfare.com/).
- <b><code>&nbsp;&nbsp;1858⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;392🍴</code></b> [TIDoS-Framework](https://github.com/theInfectedDrake/TIDoS-Framework)) - A comprehensive web application audit framework to cover up everything from Reconnaissance and OSINT to Vulnerability Analysis by [@_tID](https://github.com/theInfectedDrake).
- <b><code>&nbsp;&nbsp;&nbsp;369⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;45🍴</code></b> [numasec](https://github.com/FrancescoStabile/numasec)) - AI-driven penetration-testing platform that coordinates 10 agents and 38 vulnerability scanners covering OWASP Top 10, by [@FrancescoStabile](https://github.com/FrancescoStabile).

<a name="tools-offensive"></a>
### Offensive

<a name="tools-xss"></a>
#### XSS - Cross-Site Scripting

- <b><code>&nbsp;&nbsp;2206⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;381🍴</code></b> [xssor2](https://github.com/evilcos/xssor2)) - XSS'OR - Hack with JavaScript by [@evilcos](https://github.com/evilcos).
- <b><code>&nbsp;14959⭐</code></b> <b><code>&nbsp;&nbsp;2073🍴</code></b> [XSStrike](https://github.com/s0md3v/XSStrike)) - XSStrike is a program which can fuzz and bruteforce parameters for XSS. It can also detect and bypass WAFs by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;10861⭐</code></b> <b><code>&nbsp;&nbsp;2354🍴</code></b> [beef](https://github.com/beefproject/beef)) - The Browser Exploitation Framework Project by 🌎 [beefproject](beefproject.com).
- <b><code>&nbsp;&nbsp;&nbsp;533⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;133🍴</code></b> [JShell](https://github.com/s0md3v/JShell)) - Get a JavaScript shell with XSS by [@s0md3v](https://github.com/s0md3v).
- 🌎 [csp evaluator](csper.io/evaluator) - A tool for evaluating content-security-policies by [Csper](http://csper.io).

<a name="tools-sql-injection"></a>
#### SQL Injection

- <b><code>&nbsp;37421⭐</code></b> <b><code>&nbsp;&nbsp;6262🍴</code></b> [sqlmap](https://github.com/sqlmapproject/sqlmap)) - Automatic SQL injection and database takeover tool.

<a name="tools-template-injection"></a>
#### Template Injection

- <b><code>&nbsp;&nbsp;4156⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;684🍴</code></b> [tplmap](https://github.com/epinna/tplmap)) - Code and Server-Side Template Injection Detection and Exploitation Tool by [@epinna](https://github.com/epinna).

<a name="tools-xxe"></a>
#### XXE

- <b><code>&nbsp;&nbsp;&nbsp;659⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;115🍴</code></b> [dtd-finder](https://github.com/GoSecure/dtd-finder)) - List DTDs and generate XXE payloads using those local DTDs by [@GoSecure](https://github.com/GoSecure).

<a name="tools-csrf"></a>
#### Cross Site Request Forgery

- <b><code>&nbsp;&nbsp;1288⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;219🍴</code></b> [XSRFProbe](https://github.com/0xInfection/XSRFProbe)) - The Prime CSRF Audit & Exploitation Toolkit by [@0xInfection](https://github.com/0xinfection).

<a name="tools-ssrf"></a>
#### Server-Side Request Forgery

- 🌎 [Open redirect/SSRF payload generator](tools.intigriti.io/redirector/) - Open redirect/SSRF payload generator by 🌎 [intigriti](www.intigriti.com/).

<a name="tools-leaking"></a>
### Leaking

- <b><code>&nbsp;&nbsp;3243⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;429🍴</code></b> [CSS-Keylogging](https://github.com/maxchehab/CSS-Keylogging)) - Chrome extension and Express server that exploits keylogging abilities of CSS by [@maxchehab](https://github.com/maxchehab).
- <b><code>&nbsp;&nbsp;&nbsp;327⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;58🍴</code></b> [DVCS-Pillage](https://github.com/evilpacket/DVCS-Pillage)) - Pillage web accessible GIT, HG and BZR repositories by [@evilpacket](https://github.com/evilpacket).
- <b><code>&nbsp;&nbsp;1774⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;317🍴</code></b> [dvcs-ripper](https://github.com/kost/dvcs-ripper)) - Rip web accessible (distributed) version control systems: SVN/GIT/HG... by [@kost](https://github.com/kost).
- <b><code>&nbsp;27133⭐</code></b> <b><code>&nbsp;&nbsp;2053🍴</code></b> [gitleaks](https://github.com/zricethezav/gitleaks)) - Searches full repo history for secrets and keys by [@zricethezav](https://github.com/zricethezav).
- <b><code>&nbsp;&nbsp;2150⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;430🍴</code></b> [GitMiner](https://github.com/UnkL4b/GitMiner)) - Tool for advanced mining for content on Github by [@UnkL4b](https://github.com/UnkL4b).
- <b><code>&nbsp;&nbsp;2105⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;206🍴</code></b> [HTTPLeaks](https://github.com/cure53/HTTPLeaks)) - All possible ways, a website can leak HTTP requests by [@cure53](https://github.com/cure53).
- <b><code>&nbsp;&nbsp;&nbsp;109⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22🍴</code></b> [pwngitmanager](https://github.com/allyshka/pwngitmanager)) - Git manager for pentesters by [@allyshka](https://github.com/allyshka).
- <b><code>&nbsp;&nbsp;2105⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;229🍴</code></b> [snallygaster](https://github.com/hannob/snallygaster)) - Tool to scan for secret files on HTTP servers by [@hannob](https://github.com/hannob).
- <b><code>&nbsp;&nbsp;4355⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;655🍴</code></b> [LinkFinder](https://github.com/GerbenJavado/LinkFinder)) - Python script that finds endpoints in JavaScript files by [@GerbenJavado](https://github.com/GerbenJavado).
- <b><code>&nbsp;&nbsp;&nbsp;671⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;115🍴</code></b> [keyFinder](https://github.com/momenbasel/keyFinder)) - Chrome extension that passively scans web pages for leaked API keys, tokens, and credentials across 10 attack surfaces using 80+ detection patterns and Shannon-entropy analysis, by [@momenbasel](https://github.com/momenbasel).

<a name="tools-detecting"></a>
### Detecting

- <b><code>&nbsp;&nbsp;&nbsp;572⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;65🍴</code></b> [bXSS](https://github.com/LewisArdern/bXSS)) - bXSS is a simple Blind XSS application adapted from 🌎 [cure53.de/m](cure53.de/m) by [@LewisArdern](https://github.com/LewisArdern).
- <b><code>&nbsp;&nbsp;&nbsp;476⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;97🍴</code></b> [malware-jail](https://github.com/HynekPetrak/malware-jail)) - Sandbox for semi-automatic Javascript malware analysis, deobfuscation and payload extraction by [@HynekPetrak](https://github.com/HynekPetrak).
- <b><code>&nbsp;&nbsp;&nbsp;653⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;89🍴</code></b> [repo-supervisor](https://github.com/auth0/repo-supervisor)) - Scan your code for security misconfiguration, search for passwords and secrets.
- <b><code>&nbsp;&nbsp;4128⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;438🍴</code></b> [retire.js](https://github.com/RetireJS/retire.js)) - Scanner detecting the use of JavaScript libraries with known vulnerabilities by [@RetireJS](https://github.com/RetireJS).
- 🌎 [sqlchop](sqlchop.chaitin.cn/) - SQL injection detection engine by [chaitin](http://chaitin.com).
- 🌎 [xsschop](xsschop.chaitin.cn/) - XSS detection engine by [chaitin](http://chaitin.com).
- <b><code>&nbsp;&nbsp;2956⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;621🍴</code></b> [OpenRASP](https://github.com/baidu/openrasp)) - An open source RASP solution actively maintained by Baidu Inc. With context-aware detection algorithm the project achieved nearly no false positives. And less than 3% performance reduction is observed under heavy server load.
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [GuardRails](https://github.com/apps/guardrails)) - A GitHub App that provides security feedback in Pull Requests.

<a name="tools-preventing"></a>
### Preventing

- <b><code>&nbsp;&nbsp;5315⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;632🍴</code></b> [js-xss](https://github.com/leizongmin/js-xss)) - Sanitize untrusted HTML (to prevent XSS) with a configuration specified by a Whitelist by [@leizongmin](https://github.com/leizongmin).
- <b><code>&nbsp;&nbsp;1476⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;136🍴</code></b> [Acra](https://github.com/cossacklabs/acra)) - Client-side encryption engine for SQL databases, with strong selective encryption, SQL injections prevention and intrusion detection by 🌎 [@cossacklabs](www.cossacklabs.com/).
- <b><code>&nbsp;17008⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;848🍴</code></b> [DOMPurify](https://github.com/cure53/DOMPurify)) - DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG by 🌎 [Cure53](cure53.de/).
- 🌎 [Csper](csper.io) - A set of tools for building/evaluating/monitoring content-security-policy to prevent/detect cross site scripting by 🌎 [Csper](csper.io).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [UUSEC WAF](https://github.com/Safe3/uusec-waf/)) - An open-source web application firewall and API security gateway maintained by <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [UUCORP](https://github.com/Safe3/)).
- 🌎 [BunkerWeb](www.bunkerweb.io) - A next-generation open-source Web Application Firewall built on nginx, maintained by [Bunkerity](https://github.com/bunkerity).
- <b><code>&nbsp;&nbsp;&nbsp;145⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [FCaptcha](https://github.com/WebDecoy/FCaptcha)) - Self-hosted CAPTCHA with behavioral analysis, vision-AI agent detection, headless-browser fingerprinting, and SHA-256 proof-of-work, maintained by [WebDecoy](https://github.com/WebDecoy).
- <b><code>&nbsp;&nbsp;&nbsp;638⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;27🍴</code></b> [Pompelmi](https://github.com/pompelmi/pompelmi)) - In-process file-upload security middleware for Node.js that scans untrusted uploads before storage to detect malware, MIME spoofing, and risky archives, maintained by [pompelmi](https://github.com/pompelmi).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0🍴</code></b> [WebDecoy](https://github.com/WebDecoy/wordpress-plugin)) - Zero-configuration WordPress bot-detection plugin combining WebDriver detection, headless-browser fingerprinting, behavioral analysis, and SHA-256 proof-of-work, maintained by [WebDecoy](https://github.com/WebDecoy).
- 🌎 [CrowdSec](www.crowdsec.net/) - Open-source collaborative IPS written in Go that analyzes visitor behavior and shares threat signals across a community of operators, maintained by [CrowdSec](https://github.com/crowdsecurity).
- 🌎 [Laravel CSP Generator](csp-generator.shakiltech.com) - Interactive Content Security Policy builder for Laravel that outputs ready-to-use PHP middleware with nonce support and violation reporting, by [@itxshakil](https://github.com/itxshakil).
- <b><code>&nbsp;&nbsp;&nbsp;152⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1🍴</code></b> [verifyfetch](https://github.com/hamzaydia/verifyfetch)) - Browser-side integrity verification and resumable downloads for large files using SRI hashes, defending against CDN compromise and supply-chain attacks, by [@hamzaydia](https://github.com/hamzaydia).

<a name="tools-proxy"></a>
### Proxy

- 🌎 [Charles](www.charlesproxy.com/) - HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
- <b><code>&nbsp;43613⭐</code></b> <b><code>&nbsp;&nbsp;4569🍴</code></b> [mitmproxy](https://github.com/mitmproxy/mitmproxy)) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers by [@mitmproxy](https://github.com/mitmproxy).

<a name="tools-webshell"></a>
### Webshell

- <b><code>&nbsp;&nbsp;2044⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;249🍴</code></b> [reverse-shell](https://github.com/lukechilds/reverse-shell)) - Reverse Shell as a Service by [@lukechilds](https://github.com/lukechilds).
- <b><code>&nbsp;&nbsp;&nbsp;246⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;60🍴</code></b> [Reverse-Shell-Manager](https://github.com/WangYihang/Reverse-Shell-Manager)) - Reverse Shell Manager via Terminal [@WangYihang](https://github.com/WangYihang).
- <b><code>&nbsp;10729⭐</code></b> <b><code>&nbsp;&nbsp;5596🍴</code></b> [webshell](https://github.com/tennc/webshell)) - This is a webshell open source project by [@tennc](https://github.com/tennc).
- <b><code>&nbsp;&nbsp;&nbsp;423⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;110🍴</code></b> [Webshell-Sniper](https://github.com/WangYihang/Webshell-Sniper)) - Manage your website via terminal by [@WangYihang](https://github.com/WangYihang).
- <b><code>&nbsp;&nbsp;3517⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;630🍴</code></b> [Weevely](https://github.com/epinna/weevely3)) - Weaponized web shell by [@epinna](https://github.com/epinna).
- <b><code>&nbsp;&nbsp;&nbsp;450⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;91🍴</code></b> [nano](https://github.com/s0md3v/nano)) - Family of code golfed PHP shells by [@s0md3v](https://github.com/s0md3v).
- <b><code>&nbsp;&nbsp;2469⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;472🍴</code></b> [PhpSploit](https://github.com/nil0x42/phpsploit)) - Full-featured C2 framework which silently persists on webserver via evil PHP oneliner by [@nil0x42](https://github.com/nil0x42).

<a name="tools-disassembler"></a>
### Disassembler

- <b><code>&nbsp;&nbsp;1460⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;117🍴</code></b> [Iaitō](https://github.com/hteso/iaito)) - Qt and C++ GUI for radare2 reverse engineering framework by [@hteso](https://github.com/hteso).
- <b><code>&nbsp;&nbsp;3070⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;273🍴</code></b> [plasma](https://github.com/plasma-disassembler/plasma)) - Plasma is an interactive disassembler for x86/ARM/MIPS by [@plasma-disassembler](https://github.com/plasma-disassembler).
- <b><code>&nbsp;23872⭐</code></b> <b><code>&nbsp;&nbsp;3228🍴</code></b> [radare2](https://github.com/radare/radare2)) - Unix-like reverse engineering framework and commandline tools by [@radare](https://github.com/radare).

<a name="tools-decompiler"></a>
### Decompiler

- [CFR](http://www.benf.org/other/cfr/) - Another java decompiler by 🌎 [@LeeAtBenf](twitter.com/LeeAtBenf).

<a name="tools-dns-rebinding"></a>
### DNS Rebinding

- <b><code>&nbsp;&nbsp;&nbsp;500⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;84🍴</code></b> [DNS Rebind Toolkit](https://github.com/brannondorsey/dns-rebind-toolkit)) - DNS Rebind Toolkit is a frontend JavaScript framework for developing DNS Rebinding exploits against vulnerable hosts and services on a local area network (LAN) by [@brannondorsey](https://github.com/brannondorsey).
- <b><code>&nbsp;&nbsp;&nbsp;492⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;70🍴</code></b> [dref](https://github.com/mwrlabs/dref)) - DNS Rebinding Exploitation Framework. Dref does the heavy-lifting for DNS rebinding by [@mwrlabs](https://github.com/mwrlabs).
- <b><code>&nbsp;&nbsp;1290⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;158🍴</code></b> [Singularity of Origin](https://github.com/nccgroup/singularity)) - It includes the necessary components to rebind the IP address of the attack server DNS name to the target machine's IP address and to serve attack payloads to exploit vulnerable software on the target machine by [@nccgroup](https://github.com/nccgroup).
- <b><code>&nbsp;&nbsp;&nbsp;661⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;94🍴</code></b> [Whonow DNS Server](https://github.com/brannondorsey/whonow)) - A malicious DNS server for executing DNS Rebinding attacks on the fly by [@brannondorsey](https://github.com/brannondorsey).

<a name="tools-others"></a>
### Others

- <b><code>&nbsp;34887⭐</code></b> <b><code>&nbsp;&nbsp;3954🍴</code></b> [CyberChef](https://github.com/gchq/CyberChef)) - The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis - by [@GCHQ](https://github.com/gchq).
- 🌎 [Dnslogger](wiki.skullsecurity.org/index.php?title=Dnslogger) - DNS Logger by [@iagox86](https://github.com/iagox86).
- <b><code>&nbsp;&nbsp;&nbsp;209⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;19🍴</code></b> [cefdebug](https://github.com/taviso/cefdebug)) - Minimal code to connect to a CEF debugger by [@taviso](https://github.com/taviso).
- <b><code>&nbsp;&nbsp;1664⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;263🍴</code></b> [ctftool](https://github.com/taviso/ctftool)) - Interactive CTF Exploration Tool by [@taviso](https://github.com/taviso).
- <b><code>&nbsp;&nbsp;&nbsp;153⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26🍴</code></b> [ntlm_challenger](https://github.com/b17zr/ntlm_challenger)) - Parse NTLM over HTTP challenge messages by [@b17zr](https://github.com/b17zr).

## Social Engineering Database

- 🌎 [haveibeenpwned](haveibeenpwned.com/) - Check if you have an account that has been compromised in a data breach by 🌎 [Troy Hunt](www.troyhunt.com/).
- 🌎 [Hudson Rock](www.hudsonrock.com/threat-intelligence-cybercrime-tools) - Check if your email or domain was compromised by infostealer malware, maintained by 🌎 [Hudson Rock](www.hudsonrock.com/).

## Blogs

- 🌎 [BRETT BUERHAUS](buer.haus/) - Vulnerability disclosures and rambles on application security.
- 🌎 [Broken Browser](www.brokenbrowser.com/) - Fun with Browser Vulnerabilities.
- [James Kettle](http://albinowax.skeletonscribe.net/) - Head of Research at 🌎 [PortSwigger Web Security](portswigger.net/).
- 🌎 [leavesongs](www.leavesongs.com/) - China's talented web penetrator.
- 🌎 [n0tr00t](www.n0tr00t.com/) - ~# n0tr00t Security Team.
- 🌎 [OpnSec](opnsec.com/) - Open Mind Security!.
- [Orange](http://blog.orange.tw/) - Taiwan's talented web penetrator.
- 🌎 [Scrutiny](datarift.blogspot.tw/) - Internet Security through Web Browsers by Dhiraj Mishra.
- 🌎 [RIPS Technologies](blog.ripstech.com/tags/security/) - Write-ups for PHP vulnerabilities.
- [0Day Labs](http://blog.0daylabs.com/) - Awesome bug-bounty and challenges writeups.
- 🌎 [Blog of Osanda](osandamalith.com/) - Security Researching and Reverse Engineering.

## Twitter Users

- 🌎 [@cure53berlin](twitter.com/cure53berlin) - 🌎 [Cure53](cure53.de/) is a German cybersecurity firm.
- 🌎 [@filedescriptor](twitter.com/filedescriptor) - Active penetrator often tweets and writes useful articles.
- 🌎 [@garethheyes](twitter.com/garethheyes) - English web penetrator.
- 🌎 [@h3xstream](twitter.com/h3xstream/) - Security Researcher, interested in web security, crypto, pentest, static analysis but most of all, samy is my hero.
- 🌎 [@HackwithGitHub](twitter.com/HackwithGithub) - Initiative to showcase open source hacking tools for hackers and pentesters.
- 🌎 [@hasegawayosuke](twitter.com/hasegawayosuke) - Japanese javascript security researcher.
- 🌎 [@kinugawamasato](twitter.com/kinugawamasato) - Japanese web penetrator.
- 🌎 [@XssPayloads](twitter.com/XssPayloads) - The wonderland of JavaScript unexpected usages, and more.
- 🌎 [@shhnjk](twitter.com/shhnjk) - Web and Browsers Security Researcher.

## Practices

<a name="practices-application"></a>
### Application

- [SELinux Game](http://selinuxgame.org/) - Learn SELinux by doing. Solve Puzzles, show skillz - Written by 🌎 [@selinuxgame](twitter.com/selinuxgame).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;59⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [BadLibrary](https://github.com/SecureSkyTechnology/BadLibrary)) - Vulnerable web application for training - Written by [@SecureSkyTechnology](https://github.com/SecureSkyTechnology).
- [Hackxor](http://hackxor.net/) - Realistic web application hacking game - Written by 🌎 [@albinowax](twitter.com/albinowax).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [OWASP Juice Shop](https://github.com/bkimminich/juice-shop)) - Probably the most modern and sophisticated insecure web application - Written by [@bkimminich](https://github.com/bkimminich) and the 🌎 [@owasp_juiceshop](twitter.com/owasp_juiceshop) team.
- 🌎 [Portswigger Web Security Academy](portswigger.net/web-security) - Free trainings and labs - Written by 🌎 [PortSwigger](portswigger.net/).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;18⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;36🍴</code></b> [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store)) - Intentionally vulnerable e-commerce application built with Next.js - Written by [@kOaDT](https://github.com/kOaDT).

<a name="practices-aws"></a>
### AWS

- [FLAWS](http://flaws.cloud/) - Amazon AWS CTF challenge - Written by 🌎 [@0xdabbad00](twitter.com/0xdabbad00).
- <b><code>&nbsp;&nbsp;3601⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;749🍴</code></b> [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)) - Rhino Security Labs' "Vulnerable by Design" AWS infrastructure setup tool  - Written by [@RhinoSecurityLabs](https://github.com/RhinoSecurityLabs).

<a name="practices-xss"></a>
### XSS

- 🌎 [alert(1) to win](alf.nu/alert1) - Series of XSS challenges - Written by 🌎 [@steike](twitter.com/steike).
- [prompt(1) to win](http://prompt.ml/) - Complex 16-Level XSS Challenge held in summer 2014 (+4 Hidden Levels) - Written by [@cure53](https://github.com/cure53).
- [XSS Challenges](http://xss-quiz.int21h.jp/) - Series of XSS challenges - Written by yamagata21.
- 🌎 [XSS game](xss-game.appspot.com/) - Google XSS Challenge - Written by Google.

<a name="practices-modsecurity"></a>
### ModSecurity / OWASP ModSecurity Core Rule Set

- 🌎 [ModSecurity / OWASP ModSecurity Core Rule Set](www.netnea.com/cms/apache-tutorials/) - Series of tutorials to install, configure and tune ModSecurity and the Core Rule Set - Written by 🌎 [@ChrFolini](twitter.com/ChrFolini).

## Community

- 🌎 [Reddit](www.reddit.com/r/websecurity/)
- [Stack Overflow](http://stackoverflow.com/questions/tagged/security)

## Miscellaneous

- 🌎 [A glimpse into GitHub's Bug Bounty workflow](githubengineering.com/githubs-bug-bounty-workflow/) - Written by [@gregose](https://github.com/gregose).
- <b><code>&nbsp;&nbsp;5656⭐</code></b> <b><code>&nbsp;&nbsp;1048🍴</code></b> [awesome-bug-bounty](https://github.com/djadmin/awesome-bug-bounty)) - Comprehensive curated list of available Bug Bounty & Disclosure Programs and write-ups by [@djadmin](https://github.com/djadmin).
- [Brute Forcing Your Facebook Email and Phone Number](http://pwndizzle.blogspot.jp/2014/02/brute-forcing-your-facebook-email-and.html) - Written by [PwnDizzle](http://pwndizzle.blogspot.jp/).
- <b><code>&nbsp;&nbsp;4191⭐</code></b> <b><code>&nbsp;&nbsp;1032🍴</code></b> [bug-bounty-reference](https://github.com/ngalongc/bug-bounty-reference)) - List of bug bounty write-up that is categorized by the bug nature by [@ngalongc](https://github.com/ngalongc).
- 🌎 [Cybersecurity Campaign Playbook](www.belfercenter.org/publication/cybersecurity-campaign-playbook) - Written by 🌎 [Belfer Center for Science and International Affairs](www.belfercenter.org/).
- <b><code>&nbsp;&nbsp;4198⭐</code></b> <b><code>&nbsp;&nbsp;2078🍴</code></b> [EQGRP](https://github.com/x0rz/EQGRP)) - Decrypted content of eqgrp-auction-file.tar.xz by [@x0rz](https://github.com/x0rz).
- 🌎 [Google VRP and Unicorns](sites.google.com/site/bughunteruniversity/behind-the-scenes/presentations/google-vrp-and-unicorns) - Written by 🌎 [Daniel Stelter-Gliese](www.linkedin.com/in/daniel-stelter-gliese-170a70a2/).
- <b><code>&nbsp;&nbsp;5945⭐</code></b> <b><code>&nbsp;&nbsp;1215🍴</code></b> [Infosec_Reference](https://github.com/rmusser01/Infosec_Reference)) - Information Security Reference That Doesn't Suck by [@rmusser01](https://github.com/rmusser01).
- [Internet of Things Scanner](http://iotscanner.bullguard.com/) - Check if your internet-connected devices at home are public on Shodan by 🌎 [BullGuard](www.bullguard.com/).
- <b><code>&nbsp;&nbsp;1277⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;76🍴</code></b> [notes](https://github.com/ChALkeR/notes)) - Some public notes by [@ChALkeR](https://github.com/ChALkeR).
- [Pentest + Exploit dev Cheatsheet wallpaper](http://i.imgur.com/Mr9pvq9.jpg) - Penetration Testing and Exploit Dev CheatSheet.
- [The Definitive Security Data Science and Machine Learning Guide](http://www.covert.io/the-definitive-security-datascience-and-machinelearning-guide/) - Written by JASON TROS.
- 🌎 [$7.5k Google services mix-up](sites.google.com/site/testsitehacking/-7-5k-Google-services-mix-up) - Written by 🌎 [Ezequiel Pereira](sites.google.com/site/testsitehacking/).
- 🌎 [The Bug Hunters Methodology v2.1](docs.google.com/presentation/d/1VpRT8dFyTaFpQa9jhehtmGaC7TqQniMSYbUdlHN6VrY/edit?usp=sharing) - Written by 🌎 [@jhaddix](twitter.com/jhaddix).
- 🌎 [How I exploited ACME TLS-SNI-01 issuing Let's Encrypt SSL-certs for any domain using shared hosting](labs.detectify.com/2018/01/12/how-i-exploited-acme-tls-sni-01-issuing-lets-encrypt-ssl-certs-for-any-domain-using-shared-hosting/) - Written by 🌎 [@fransrosen](twitter.com/fransrosen).
- 🌎 [TL:DR: VPN leaks users’ IPs via WebRTC. I’ve tested seventy VPN providers and 16 of them leaks users’ IPs via WebRTC (23%)](voidsec.com/vpn-leak/) - Written by 🌎 [voidsec](voidsec.com/).
- 🌎 [Be careful what you copy: Invisibly inserting usernames into text with Zero-Width Characters](medium.com/@umpox/be-careful-what-you-copy-invisibly-inserting-usernames-into-text-with-zero-width-characters-18b4e6f17b66) - Written by 🌎 [@umpox](medium.com/@umpox).
- 🌎 [Escape and Evasion Egressing Restricted Networks](www.optiv.com/blog/escape-and-evasion-egressing-restricted-networks) - Written by [Chris Patten, Tom Steele](mailto:info@optiv.com).
- 🌎 [Domato Fuzzer's Generation Engine Internals](www.sigpwn.io/blog/2018/4/14/domato-fuzzers-generation-engine-internals) - Written by 🌎 [sigpwn](www.sigpwn.io/).
- 🌎 [CSS Is So Overpowered It Can Deanonymize Facebook Users](www.evonide.com/side-channel-attacking-browsers-through-css3-features/) - Written by 🌎 [Ruslan Habalov](www.evonide.com/).
- 🌎 [Introduction to Web Application Security](www.slideshare.net/nragupathy/introduction-to-web-application-security-blackhoodie-us-2018) - Written by 🌎 [@itsC0rg1](twitter.com/itsC0rg1), 🌎 [@jmkeads](twitter.com/jmkeads) and 🌎 [@matir](twitter.com/matir).
- 🌎 [Finding The Real Origin IPs Hiding Behind CloudFlare or TOR](www.secjuice.com/finding-real-ips-of-origin-servers-behind-cloudflare-or-tor/) - Written by 🌎 [Paul Dannewitz](www.secjuice.com/author/paul-dannewitz/).
- 🌎 [How I could have stolen your photos from Google - my first 3 bug bounty writeups](blog.avatao.com/How-I-could-steal-your-photos-from-Google/) - Written by 🌎 [@gergoturcsanyi](twitter.com/gergoturcsanyi).
- 🌎 [An example why NAT is NOT security](0day.work/an-example-why-nat-is-not-security/) - Written by 🌎 [@0daywork](twitter.com/@0daywork).
- 🌎 [Alexa Top 1 Million Security - Hacking the Big Ones](slashcrypto.org/data/itsecx2018.pdf) - Written by 🌎 [@slashcrypto](twitter.com/slashcrypto).
- 🌎 [Hacking with a Heads Up Display](segment.com/blog/hacking-with-a-heads-up-display/) - Written by 🌎 [David Scrobonia](segment.com/blog/authors/david-scrobonia/).
- 🌎 [WEB APPLICATION PENETRATION TESTING NOTES](techvomit.net/web-application-penetration-testing-notes/) - Written by 🌎 [Jayson](techvomit.net/).
- 🌎 [List of bug bounty writeups](pentester.land/list-of-bug-bounty-writeups.html) - Written by 🌎 [Mariem](pentester.land/).
- [The bug bounty program that changed my life](http://10degres.net/the-bug-bounty-program-that-changed-my-life/) - Written by [Gwen](http://10degres.net/).
- 🌎 [Why Facebook's api starts with a for loop](dev.to/antogarand/why-facebooks-api-starts-with-a-for-loop-1eob) - Written by 🌎 [@AntoGarand](twitter.com/AntoGarand).
- 🌎 [Implications of Loading .NET Assemblies](threatvector.cylance.com/en_us/home/implications-of-loading-net-assemblies.html) - Written by 🌎 [Brian Wallace](threatvector.cylance.com/en_us/contributors/brian-wallace.html).
- 🌎 [WCTF2019: Gyotaku The Flag](westerns.tokyo/wctf2019-gtf/wctf2019-gtf-slides.pdf) - Written by 🌎 [@t0nk42](twitter.com/t0nk42).
- 🌎 [How we abused Slack's TURN servers to gain access to internal services](www.rtcsec.com/2020/04/01-slack-webrtc-turn-compromise/) - Written by 🌎 [@sandrogauci](twitter.com/sandrogauci).
- 🌎 [DOS File Path Magic Tricks](medium.com/walmartlabs/dos-file-path-magic-tricks-5eda7a7a85fa) - Written by 🌎 [@clr2of8](medium.com/@clr2of8).
- 🌎 [How I got my first big bounty payout with Tesla](medium.com/heck-the-packet/how-i-got-my-first-big-bounty-payout-with-tesla-8d28b520162d) - Written by 🌎 [@cj.fairhead](medium.com/@cj.fairhead).
- 🌎 [Grokking Web Application Security](www.manning.com/books/grokking-web-application-security) - Hands-on introduction to web application security fundamentals by Malcolm McDonald (Manning).
- <b><code>&nbsp;&nbsp;&nbsp;&nbsp;78⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;13🍴</code></b> [htb-writeups](https://github.com/momenbasel/htb-writeups)) - Comprehensive Hack The Box writeup collection covering 75+ web challenges including XSS, SQLi, SSTI, SSRF, and deserialization, by [@momenbasel](https://github.com/momenbasel).

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](code-of-conduct.md). By participating in this project you agree to abide by its terms.

## License

[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0/)

To the extent possible under law, 🌎 [@qazbnm456](qazbnm456.github.io/) has waived all copyright and related or neighboring rights to this work.

## Source
<b><code>&nbsp;13380⭐</code></b> <b><code>&nbsp;&nbsp;1779🍴</code></b> [qazbnm456/awesome-web-security](https://github.com/qazbnm456/awesome-web-security))
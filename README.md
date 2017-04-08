# 超棒应用程序安全清单 [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

[English Version](https://github.com/paragonie/awesome-appsec)

学习应用程序安全性的资源列表，包含书籍，网站，博客文章和自我评估测验等，由[Paragon Initiative Enterprises](https://paragonie.com)公司维护，由应用安全开发社区贡献，我们[其他社区项目](https://paragonie.com/projects)可能对未来的应用安全领域也有用哦，如果你是应用安全的小白，那可能会从[深入浅出讲应用安全](https://paragonie.com/blog/2015/08/gentle-introduction-application-security)一文中受益。

# 贡献

[请参考贡献指南了解详情](https://github.com/paragonie/awesome-appsec/blob/master/CONTRIBUTING.md).

# 目录

  * [通用](#通用)
    * [文章](#文章)
      * [<a href="http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/">如何安全地生成随机数</a> (2014)](#如何安全地生成随机数-2014)
      * [<a href="https://crackstation.net/hashing-security.htm">加盐哈希密码的正确姿势</a> (2014)](#加盐哈希密码的正确姿势-2014)
      * [<a href="http://insanecoding.blogspot.co.uk/2014/05/a-good-idea-with-bad-usage-devurandom.html">/dev/urandom不当的使用</a> (2014)](#devurandom不当使用-2014)
      * [<a href="https://paragonie.com/white-paper/2015-why-invest-application-security">Why Invest in Application Security?</a> (2015)](#why-invest-in-application-security-2015)
      * [<a href="https://freedom-to-tinker.com/blog/jbonneau/be-wary-of-one-time-pads-and-other-crypto-unicorns/">警惕多次使用一次性密钥和其他奇葩的加密方式</a> (2015)](#警惕多次使用一次性密钥和其他奇葩的加密方式-2015)
    * [书籍](#书籍)
      * [<a href="https://zhuanlan.zhihu.com/p/23561475">作为一个渗透测试学习者必知必读的好书推荐</a>](#作为一个渗透测试学习者必知必读的好书推荐)
      * [<a href="https://zhuanlan.zhihu.com/p/23574346">作为一个二进制安全学习者必知必读的书籍推荐</a>](#作为一个二进制安全学习者必知必读的书籍推荐)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://mdsec.net/wahh">Web应用黑客手册</a> (2011)](#-web应用黑客手册-2011)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Cryptography-Engineering-Principles-Practical-Applications/dp/0470474246">密码学工程：设计原理与实践应用 </a> (2010)](#-密码学工程设计原理与实践应用--2010)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921">Python灰帽子：黑客与逆向工程师的Python编程之道</a> (2009)](#-python灰帽子黑客与逆向工程师的python编程之道-2009)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/The-Software-Security-Assessment-Vulnerabilities/dp/0321444426/">软件安全评估的艺术:识别与防范软件</a> (2006)](#-软件安全评估的艺术识别与防范软件-2006)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Interfaces-Implementations-Techniques-Creating-Reusable/dp/0201498413/">C语言接口与实现：创建可重用软件的技术</a> (1996)](#-c语言接口与实现创建可重用软件的技术-1996)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817">逆向：逆向工程的秘密</a> (2005)](#-逆向逆向工程的秘密-2005)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/JavaScript-Good-Parts-Douglas-Crockford/dp/0596517742">JavaScript语言精粹</a> (2008)](#-javascript语言精粹-2008)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Windows®-Internals-Including-Developer-Reference/dp/0735625301">Windows内部实现:囊括Windows Server 2008和Windows Vista</a> (2007)](#-windows内部实现囊括windows-server-2008和windows-vista-2007)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/The-Hackers-Handbook-Charlie-Miller/dp/0470395362">Mac黑客手册</a> (2009)](#-mac黑客手册-2009)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/The-IDA-Pro-Book-Disassembler/dp/1593271786">IDA Pro权威指南:世界上最受欢迎反汇编者的非正式指南</a> (2008)](#-ida-pro权威指南世界上最受欢迎反汇编者的非正式指南-2008)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Internetworking-TCP-Vol-Implementation-Internals/dp/0139738436">用TCP/IP进行网际互连（第2卷）：设计、实现与内核（ANSI C版）（第3版）</a> (1998)](#-用tcpip进行网际互连第2卷设计实现与内核ansi-c版第3版-1998)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Network-Algorithmics-Interdisciplinary-Designing-Networking/dp/0120884771">网络算法：设计快速网络设备的跨学科方法</a> (2004)](#-网络算法设计快速网络设备的跨学科方法-2004)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Computation-Structures-Electrical-Engineering-Computer/dp/0262231395">计算机结构 (麻省理工学院电子电气工程与计算机科学系教材)</a> (1989)](#-计算机结构-麻省理工学院电子电气工程与计算机科学系教材-1989)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Surreptitious-Software-Obfuscation-Watermarking-Tamperproofing/dp/0321549252">软件加密与解密</a> (2009)](#-软件加密与解密-2009)
      * [<a href="http://www.dwheeler.com/secure-programs/">安全编程：开发安全程序</a> (2015)](#安全编程开发安全程序-2015)
      * [<a href="https://www.cl.cam.ac.uk/~rja14/book.html">安全工程：构建可靠分布式系统指南（第二版）</a> (2008)](#安全工程构建可靠分布式系统指南第二版-2008)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="https://www.feistyduck.com/books/bulletproof-ssl-and-tls/">防弹SSL和TLS：理解和部署SSL/TLS和PKI以保护服务器和Web应用安全</a> (2014)](#-防弹ssl和tls理解和部署ssltls和pki以保护服务器和web应用安全-2014)
    * [课程](#课程)
      * [<a href="https://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/">计算机安全攻击（CIS 4930）FSU</a>](#计算机安全攻击cis-4930fsu)
      * [<a href="https://github.com/isislab/Hack-Night">黑客之夜</a>](#黑客之夜)
    * [网站](#网站)
      * [<a href="http://www.hackthissite.org">Hack This Site!</a>](#hack-this-site)
      * [<a href="http://www.enigmagroup.org">Enigma Group</a>](#enigma-group)
      * [<a href="https://timoh6.github.io/WebAppSecQuiz/">Web App Sec Quiz</a>](#web-app-sec-quiz)
      * [<a href="https://securepasswords.info">SecurePasswords.info</a>](#securepasswordsinfo)
      * [<a href="http://lzone.de/cheat-sheet/Security-News-Feeds">Security News Feeds Cheat-Sheet</a>](#security-news-feeds-cheat-sheet)
      * [<a href="http://opensecuritytraining.info/">Open Security Training</a>](#open-security-training)
      * [<a href="https://microcorruption.com/login">MicroCorruption</a>](#microcorruption)
      * [<a href="http://cryptopals.com">The Matasano Crypto Challenges</a>](#the-matasano-crypto-challenges)
      * [<a href="https://pentesterlab.com">PentesterLab</a>](#pentesterlab)
      * [<a href="https://bkimminich.github.io/juice-shop">Juice Shop</a>](#juice-shop)
      * [<a href="http://hackyourselffirst.troyhunt.com/">Supercar Showdown</a>](#supercar-showdown)
      * [博客](#博客)
        * [<a href="http://cryptofails.com">Crypto Fails</a>](#crypto-fails)
        * [<a href="https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/">NCC Group</a>](#ncc-group)
        * [<a href="https://scotthelme.co.uk">Scott Helme</a>](#scott-helme)
      * [Wiki](#wiki)
        * [<a href="https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project">OWASP Top Ten Project</a>](#owasp-top-ten-project)
      * [工具](#工具)
        * [<a href="https://www.ssllabs.com/">Qualys SSL Labs</a>](#qualys-ssl-labs)
        * [<a href="https://securityheaders.io/">securityheaders.io</a>](#securityheadersio)
        * [<a href="https://report-uri.io">report-uri.io</a>](#report-uriio)
  * [Android](#android)
    * [书籍](#书籍-1)
      * [<a href="https://www.securecoding.cert.org/confluence/display/android/Android Secure Coding Standard">Android安全编码标准</a> (2015)](#android安全编码标准-2015)
  * [C](#c)
    * [书籍](#书籍-2)
      * [<a href="https://www.securecoding.cert.org/confluence/display/c/SEI CERT C Coding Standard">C安全编码标准</a> (2006)](#c安全编码标准-2006)
      * [<a href="https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/index.html">防御性编码：Fedora安全团队提高软件安全指南</a> (2016)](#防御性编码fedora安全团队提高软件安全指南-2016)
  * [C  ](#c-1)
    * [书籍](#书籍-3)
      * [<a href="https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637">C  安全编码标准</a> (2006)](#c安全编码标准-2006-1)
  * [C Sharp](#c-sharp)
    * [书籍](#书籍-4)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://securitydriven.net/">安全驱动.NET</a> (2015)](#-安全驱动net-2015)
  * [Java](#java)
    * [书籍](#书籍-5)
      * [<a href="https://www.securecoding.cert.org/confluence/display/java/SEI CERT Oracle Coding Standard for Java">Java安全编码标准</a> (2007)](#java安全编码标准-2007)
      * [<a href="http://www.oracle.com/technetwork/java/seccodeguide-139067.html">Java SE安全编指南</a> (2014)](#java-se安全编指南-2014)
  * [Node.js](#nodejs)
    * [文章](#文章-1)
      * [<a href="https://blog.risingstack.com/node-js-security-checklist/">Node.js安全检查清单</a> (2015)](#nodejs安全检查清单-2015)
    * [培训](#培训)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="https://liftsecurity.io/training">Lift Security团队的安全培训</a>](#-lift-security团队的安全培训)
  * [Perl](#perl)
    * [书籍](#书籍-6)
      * [<a href="https://www.securecoding.cert.org/confluence/display/perl/SEI CERT Perl Coding Standard">Perl安全编码标准</a> (2011)](#perl安全编码标准-2011)
  * [Python](#python)
    * [书籍](#书籍-7)
      * [<a href="https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/chap-Defensive_Coding-Python.html">Fedora防御编码指南中的Python章节</a>](#fedora防御编码指南中的python章节)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="http://www.amazon.com/Violent-Python-Cookbook-Penetration-Engineers/dp/1597499579">Violent Python</a>](#-violent-python)
    * [网站](#网站-1)
      * [<a href="https://github.com/ebranca/owasp-pysec/wiki">开放式Web应用程序安全项目中的Python安全Wiki</a> (2014)](#开放式web应用程序安全项目中的python安全wiki-2014)
  * [Ruby](#ruby)
    * [书籍](#书籍-8)
      * [<a href="https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Secure_Ruby_Development_Guide/index.html">Ruby安全开发指南</a> (2014)](#ruby安全开发指南-2014)
  * [PHP](#php)
    * [文章](#文章-2)
      * [<a href="http://blog.ircmaxell.com/2014/11/its-all-about-time.html">关于时间的一切</a> (2014)](#关于时间的一切-2014)
      * [<a href="https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence">实现PHP长期持久性安全认证</a> (2015)](#实现php长期持久性安全认证-2015)
      * [<a href="http://blog.astrumfutura.com/2013/04/20-point-list-for-preventing-cross-site-scripting-in-php">PHP中防止跨站脚本攻击20个点子</a> (2013)](#php中防止跨站脚本攻击20个点子-2013)
      * [<a href="http://www.cyberciti.biz/tips/php-security-best-practices-tutorial.html">针对系统管理员最佳PHP安全配置25点建议</a> (2011)](#针对系统管理员最佳php安全配置25点建议-2011)
      * [<a href="https://timoh6.github.io/2014/06/16/PHP-data-encryption-cheatsheet.html">PHP数据加密入门介绍</a> (2014)](#php数据加密入门介绍-2014)
      * [<a href="https://paragonie.com/blog/2015/05/preventing-sql-injection-in-php-applications-easy-and-definitive-guide">PHP应用程序防止SQL注入简明指南</a> (2014)](#php应用程序防止sql注入简明指南-2014)
      * [<a href="https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded">你不该使用Base64密码</a> (2015)](#你不该使用base64密码-2015)
      * [<a href="https://paragonie.com/white-paper/2015-secure-php-data-encryption">PHP应用程序安全数据加密指南</a> (2015)](#php应用程序安全数据加密指南-2015)
    * [书籍](#书籍-9)
      * [<a href="img/nonfree.png" target="_blank"><img src="img/nonfree.png" alt="nonfree" style="max-width:100\x;"></a> <a href="https://leanpub.com/securingphp-coreconcepts">PHP安全：核心理念</a>](#-php安全核心理念)
      * [<a href="https://paragonie.com/book/pecl-libsodium">PHP项目中使用Libsodium</a>](#php项目中使用libsodium)
    * [干货库](#干货库)
      * [<a href="https://github.com/defuse/php-encryption">defuse/php-encryption</a>](#defusephp-encryption)
      * [<a href="https://github.com/ircmaxell/password_compat">ircmaxell/password_compat</a>](#ircmaxellpassword_compat)
      * [<a href="https://github.com/ircmaxell/RandomLib">ircmaxell/RandomLib</a>](#ircmaxellrandomlib)
      * [<a href="https://github.com/thephpleague/oauth2-server">thephpleague/oauth2-server</a>](#thephpleagueoauth2-server)
      * [<a href="https://github.com/paragonie/random_compat">paragonie/random_compat</a>](#paragonierandom_compat)
      * [<a href="https://github.com/psecio/gatekeeper">psecio/gatekeeper</a>](#pseciogatekeeper)
      * [<a href="http://www.openwall.com/phpass/">openwall/phpass</a>](#openwallphpass)
    * [网站](#网站-2)
      * [<a href="http://websec.io">websec.io</a>](#websecio)
      * [博客](#博客-1)
        * [<a href="https://paragonie.com/blog/">Paragon Initiative Enterprises Blog</a>](#paragon-initiative-enterprises-blog)
        * [<a href="http://blog.ircmaxell.com">ircmaxell's blog</a>](#ircmaxells-blog)
        * [<a href="http://blog.astrumfutura.com">Pádraic Brady's Blog</a>](#pádraic-bradys-blog)
      * [订阅](#订阅)
        * [<a href="http://securingphp.com">Securing PHP Weekly</a>](#securing-php-weekly)


# 通用

## 文章

### [如何安全地生成随机数](http://sockpuppet.org/blog/2014/02/25/safely-generate-random-numbers/) (2014)

关于加密安全中的伪随机数生成器的建议。

### [加盐哈希密码的正确姿势](https://crackstation.net/hashing-security.htm) (2014)

[Crackstation](https://crackstation.net)上的一篇文章, [Defuse Security](https://defuse.ca)的一个项目。

### [/dev/urandom不当使用](http://insanecoding.blogspot.co.uk/2014/05/a-good-idea-with-bad-usage-devurandom.html) (2014)

在Linux/BSD上提及了许多使 `/dev/urandom`失效的方法。

### [Why Invest in Application Security?](https://paragonie.com/white-paper/2015-why-invest-application-security) (2015)

经营业务需要具有成本意识，并尽量减少不必要的支出。确保您的应用程序的安全性的好处对于大多数公司来说是不可见的，因此通常他们忽视投资于安全软件开发作为一种节省成本的措施，然而这些公司并没有意识到的潜在的数据泄露威胁，**平均数据泄露造成数百万美元的损失**，因此对于大多数公司来说投入更多的时间和人力开发安全软件是值得的，能尽量减少这种风险。

### [警惕多次使用一次性密钥和其他奇葩的加密方式](https://freedom-to-tinker.com/blog/jbonneau/be-wary-of-one-time-pads-and-other-crypto-unicorns/) (2015)

任何想要够建立加密功能的开发者**必读**的好文。

## 书籍

### [作为一个渗透测试学习者必知必读的好书推荐](https://zhuanlan.zhihu.com/p/23561475)

### [作为一个二进制安全学习者必知必读的书籍推荐](https://zhuanlan.zhihu.com/p/23574346)

### ![nonfree](img/nonfree.png) [Web应用黑客手册](http://mdsec.net/wahh) (2011)

### ![nonfree](img/nonfree.png) [密码学工程：设计原理与实践应用 ](http://www.amazon.com/Cryptography-Engineering-Principles-Practical-Applications/dp/0470474246) (2010)

### ![nonfree](img/nonfree.png) [Python灰帽子：黑客与逆向工程师的Python编程之道](http://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921) (2009)

### ![nonfree](img/nonfree.png) [软件安全评估的艺术:识别与防范软件](http://www.amazon.com/The-Software-Security-Assessment-Vulnerabilities/dp/0321444426/) (2006)

### ![nonfree](img/nonfree.png) [C语言接口与实现：创建可重用软件的技术](http://www.amazon.com/Interfaces-Implementations-Techniques-Creating-Reusable/dp/0201498413/) (1996)

### ![nonfree](img/nonfree.png) [逆向：逆向工程的秘密](http://www.amazon.com/Reversing-Secrets-Engineering-Eldad-Eilam/dp/0764574817) (2005)


### ![nonfree](img/nonfree.png) [JavaScript语言精粹](http://www.amazon.com/JavaScript-Good-Parts-Douglas-Crockford/dp/0596517742) (2008)

### ![nonfree](img/nonfree.png) [Windows内部实现:囊括Windows Server 2008和Windows Vista](http://www.amazon.com/Windows%C2%AE-Internals-Including-Developer-Reference/dp/0735625301) (2007)

### ![nonfree](img/nonfree.png) [Mac黑客手册](http://www.amazon.com/The-Hackers-Handbook-Charlie-Miller/dp/0470395362) (2009)

### ![nonfree](img/nonfree.png) [IDA Pro权威指南:世界上最受欢迎反汇编者的非正式指南](http://www.amazon.com/The-IDA-Pro-Book-Disassembler/dp/1593271786) (2008)

### ![nonfree](img/nonfree.png) [用TCP/IP进行网际互连（第2卷）：设计、实现与内核（ANSI C版）（第3版）](http://www.amazon.com/Internetworking-TCP-Vol-Implementation-Internals/dp/0139738436) (1998)

### ![nonfree](img/nonfree.png) [网络算法：设计快速网络设备的跨学科方法](http://www.amazon.com/Network-Algorithmics-Interdisciplinary-Designing-Networking/dp/0120884771) (2004)

### ![nonfree](img/nonfree.png) [计算机结构 (麻省理工学院电子电气工程与计算机科学系教材)](http://www.amazon.com/Computation-Structures-Electrical-Engineering-Computer/dp/0262231395) (1989)

### ![nonfree](img/nonfree.png) [软件加密与解密](http://www.amazon.com/Surreptitious-Software-Obfuscation-Watermarking-Tamperproofing/dp/0321549252) (2009)

### [安全编程：开发安全程序](http://www.dwheeler.com/secure-programs/) (2015)

### [安全工程：构建可靠分布式系统指南（第二版）](https://www.cl.cam.ac.uk/~rja14/book.html) (2008)

### ![nonfree](img/nonfree.png) [防弹SSL和TLS：理解和部署SSL/TLS和PKI以保护服务器和Web应用安全](https://www.feistyduck.com/books/bulletproof-ssl-and-tls/) (2014)

## 课程

### [计算机安全攻击（CIS 4930）FSU](https://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/)

佛罗里达州立大学Owen Redwood教授的漏洞研究和攻击课程。

**一定要看看[讲座](https://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/lectures.html)！**

### [黑客之夜](https://github.com/isislab/Hack-Night)

由纽约大学理工学院的旧渗透测试和漏洞分析课程发展而来，黑客之夜课程清晰明了地介绍各种安全攻击。

## 网站

### [Hack This Site!](http://www.hackthissite.org)

通过尝试黑掉网站了解应用程序安全。

### [Enigma Group](http://www.enigmagroup.org)

黑客和安全专家训练靶场。

### [Web App Sec Quiz](https://timoh6.github.io/WebAppSecQuiz/)

自我评估测验Web应用安全。

### [SecurePasswords.info](https://securepasswords.info)

在几种语言/框架中安全的密码。

### [Security News Feeds Cheat-Sheet](http://lzone.de/cheat-sheet/Security-News-Feeds)

有关安全新闻来源列表。

### [Open Security Training](http://opensecuritytraining.info/)

有关开放的x86编程，黑客和取证培训的视频课程。

### [MicroCorruption](https://microcorruption.com/login)

CTF比赛形式地学习汇编和嵌入式设备安全。

### [The Matasano Crypto Challenges](http://cryptopals.com)

由[Matasano Security](http://matasano.com)编写的一系列编程练习，Maciej Ceglowski给了详细[介绍](https://blog.pinboard.in/2013/04/the_matasano_crypto_challenges)。

### [PentesterLab](https://pentesterlab.com)

PentesterLab提供[免费的实践练习](https://pentesterlab.com/exercises/) 和[学习规划指南](https://pentesterlab.com/bootcamp/) 。

### [Juice Shop](https://bkimminich.github.io/juice-shop)

存在安全隐患的Javascript Web应用程序练习靶场。

### [Supercar Showdown](http://hackyourselffirst.troyhunt.com/)

通过学习实际的网络攻击来提高自身的安全技能。

### 博客

#### [Crypto Fails](http://cryptofails.com)

详解具有安全隐患的加密技术。

#### [NCC Group](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/)

国家计算中心（National Computing Centre）博客

#### [Scott Helme](https://scotthelme.co.uk)

学习有关安全和性能方面的知识。

### Wiki

#### [OWASP Top Ten Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)

Web应用程序中常见的十大安全漏洞。

### 工具

#### [Qualys SSL Labs](https://www.ssllabs.com/)

著名的SSL和TLS攻击工具套件。

#### [securityheaders.io](https://securityheaders.io/)

轻松快速地评估HTTP响应标头的安全性。

#### [report-uri.io](https://report-uri.io)

免费的内容安全策略（Content Security Policy，CSP）和HTTP公钥钉扎（HTTP Public Key Pinning，HPKP）报告服务。

# Android

## 书籍

### [Android安全编码标准](https://www.securecoding.cert.org/confluence/display/android/Android+Secure+Coding+Standard) (2015)

由软件工程协会计算机安全应急响应组编写，详细地介绍了Android开发的安全编码标准。

# C

## 书籍

### [C安全编码标准](https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard) (2006)

由软件工程协会计算机安全应急响应组编写，详细地介绍了C开发的安全编码标准。

### [防御性编码：Fedora安全团队提高软件安全指南](https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/index.html) (2016)

通过介绍安全编码来提供提高软件安全的指导。 涵盖常见的编程语言和库，并着重于具体建议。

# C++

## 书籍

### [C++安全编码标准](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637) (2006)

由软件工程协会计算机安全应急响应组编写，详细地介绍了C++开发的安全编码标准。

# C Sharp

## 书籍

### ![nonfree](img/nonfree.png) [安全驱动.NET](http://securitydriven.net/) (2015)

介绍如何开发基于.NET Framework 4.5 安全的应用程序，具体涵盖加密和安全工程领域。

# Java

## 书籍

### [Java安全编码标准](https://www.securecoding.cert.org/confluence/display/java/SEI+CERT+Oracle+Coding+Standard+for+Java) (2007)

由软件工程协会计算机安全应急响应组编写，详细地介绍Java开发的安全编码标准。

### [Java SE安全编指南](http://www.oracle.com/technetwork/java/seccodeguide-139067.html) (2014)

使用Oracle安全的Java编程指南。

# Node.js

## 文章

### [Node.js安全检查清单](https://blog.risingstack.com/node-js-security-checklist/) (2015)

提供了开发安全Node.js应用程序许多有用帮助信息。

## 培训

### ![nonfree](img/nonfree.png) [Lift Security团队的安全培训](https://liftsecurity.io/training)

[Node安全培训](https://nodesecurity.io)

# Perl

## 书籍

### [Perl安全编码标准](https://www.securecoding.cert.org/confluence/display/perl/SEI+CERT+Perl+Coding+Standard) (2011)

由软件工程协会计算机安全应急响应组编写，详细地介绍了C++开发的安全编码标准。

# Python

## 书籍

### [Fedora防御编码指南中的Python章节](https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Defensive_Coding/chap-Defensive_Coding-Python.html)

列出应尽量避免的函数，参考其他介绍有关Python编码安全章节。

### ![nonfree](img/nonfree.png) [Violent Python](http://www.amazon.com/Violent-Python-Cookbook-Penetration-Engineers/dp/1597499579)

展示如何从对攻击性计算概念的理论认识转变为实际实现。

## 网站

### [开放式Web应用程序安全项目中的Python安全Wiki](https://github.com/ebranca/owasp-pysec/wiki) (2014)

开放式Web应用程序安全项目中的Python安全Wiki。

# Ruby

## 书籍

### [Ruby安全开发指南](https://docs.fedoraproject.org/en-US/Fedora_Security_Team/1/html/Secure_Ruby_Development_Guide/index.html) (2014)

Fedora安全团队确保Ruby安全开发的指南，可在[Github](https://github.com/jrusnack/secure-ruby-development-guide)上获取。

# PHP

## 文章

### [关于时间的一切](http://blog.ircmaxell.com/2014/11/its-all-about-time.html) (2014)

深入浅出地介绍PHP应用程序中的有关时序攻击。

### [实现PHP长期持久性安全认证](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence) (2015)

讨论密码策略，密码存储，“记住我”，Cookie和帐户恢复相关话题。

### [PHP中防止跨站脚本攻击20个点子](http://blog.astrumfutura.com/2013/04/20-point-list-for-preventing-cross-site-scripting-in-php) (2013)

Padriac Brady给出的关于构建不易受XSS影响的程序建议

### [针对系统管理员最佳PHP安全配置25点建议](http://www.cyberciti.biz/tips/php-security-best-practices-tutorial.html) (2011)

虽然这篇文章有点久了，不过面向PHP 7，其中大部分的建议仍然是极具参考价值的。

### [PHP数据加密入门介绍](https://timoh6.github.io/2014/06/16/PHP-data-encryption-cheatsheet.html) (2014)

@timoh6详细介绍PHP数据加密的实现。

### [PHP应用程序防止SQL注入简明指南](https://paragonie.com/blog/2015/05/preventing-sql-injection-in-php-applications-easy-and-definitive-guide) (2014)

简单明了地介绍如何防止SQL注入。

### [你不该使用Base64密码](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded) (2015)

通常被误用的加密术语和基本概念的可读概述，以PHP中的代码为示例，如果您对加密术语感到困惑，就从这里开始学习吧。

### [PHP应用程序安全数据加密指南](https://paragonie.com/white-paper/2015-secure-php-data-encryption) (2015)

讨论端到端网络层加密（HTTPS）的重要性以及静态数据的安全加密，然后介绍开发人员应该为特定用例使用的特定加密工具， [libsodium](https://pecl.php.net/package/libsodium)、[增强防御的安全PHP加密库](https://github.com/defuse/php-encryption)以及OpenSSL。

## 书籍

### ![nonfree](img/nonfree.png) [PHP安全：核心理念](https://leanpub.com/securingphp-coreconcepts)

介绍了一些最常见的安全性方面知识，并提供PHP其中常见的一些例子。

### [PHP项目中使用Libsodium](https://paragonie.com/book/pecl-libsodium)

调用libsodium加密库快速开发安全和可靠的应用程序。

## 干货库

### [defuse/php-encryption](https://github.com/defuse/php-encryption)

用于PHP应用程序的对称密钥加密库。

### [ircmaxell/password_compat](https://github.com/ircmaxell/password_compat)

如果你使用PHP 5.3.7+或5.4，可以使用这个库来哈希密码。

### [ircmaxell/RandomLib](https://github.com/ircmaxell/RandomLib)

用于生成随机字符串或数字。

### [thephpleague/oauth2-server](https://github.com/thephpleague/oauth2-server)

安全的OAuth2服务器实现。

### [paragonie/random_compat](https://github.com/paragonie/random_compat)

PHP 7提供了一组新的伪随机数生成器（Cryptographically Secure Pseudo-Random Number Generato，CSPRNG）函数：`random_bytes()`和`random_int()`， 社区致力于在PHP 5（向前兼容）中提供公开统一的API。

### [psecio/gatekeeper](https://github.com/psecio/gatekeeper)

一个安全的认证和授权库，基于角色的访问控制实现和[Paragon Initiative Enterprise公司](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence#title.2)给出的安全“记住我”复选框建议。

### [openwall/phpass](http://www.openwall.com/phpass/)

用于PHP应用程序的便携式公有领域密码哈希框架。

## 网站

### [websec.io](http://websec.io)

致力于通过基础安全知识，新兴技术和PHP安全编码相关的主题来提高开发人员有关安全意识。

### 博客

#### [Paragon Initiative Enterprises Blog](https://paragonie.com/blog/)

位于佛罗里达州奥兰多安全技术咨询公司博客

#### [ircmaxell's blog](http://blog.ircmaxell.com)

介绍关于PHP安全和性能以及Web应用程序开发的博客。

#### [Pádraic Brady's Blog](http://blog.astrumfutura.com)

PádraicBrady是Zend Framework领域的安全专家。

### 订阅

#### [Securing PHP Weekly](http://securingphp.com)

每周更新有关PHP安全知识。



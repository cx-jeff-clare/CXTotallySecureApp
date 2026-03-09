[![Build Status](https://travis-ci.org/k-tamura/easybuggy4sb.svg?branch=master)](https://travis-ci.org/k-tamura/easybuggy4sb)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/k-tamura/easybuggy4sb.svg)](https://github.com/k-tamura/easybuggy4sb/releases/latest)

![Checkmarx Logo](https://checkmarx.com/wp-content/uploads/2021/04/cx_logo-header.png)

# TotallySecureApp! :lock:

This project is intended to accompany the [Checkmarx Developer Workshops](https://workshops.checkmarx.com).  This is a clone of EasyBuggy built on Spring Boot. [EasyBuggy](https://github.com/k-tamura/easybuggy) is a broken web application in order to understand behavior of bugs and vulnerabilities, for example, [memory leak, deadlock, JVM crash, SQL injection and so on](https://github.com/k-tamura/easybuggy4sb/wiki).

As you may have gathered, this app isn't totally secure... actually far from it.  We use this source code to illustrate features, capabilities, and concepts within our Checkmarx workshops.

Note that if this application is run, this Java application can result in system crashes as a result of memory leaks, deadlock, JVM crashes, etc. In these labs, we are only using Checkmarx solutions that scan source code, thus there is no reason or need to run this project and __it is not recommended to do so__. If you do wish to run the project, do so at your own risk. It is HIGHLY recommended you do so in a sandbox environment (e.g. within a VM)

    
:clock4: For more detail
-
   
See [the wiki page](https://github.com/k-tamura/easybuggy4sb/wiki).

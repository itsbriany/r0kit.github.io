---
layout: single
title:  "Bug Hunting Methodology - Open Redirect"
date:   2020-08-15
excerpt: "My bug hunting methodology on finding open redirect bugs in web apps."
categories:
  - bug hunting
  - infosec
tags:
  - open redirect
---

Open redirects abuse trust within domains where the user is redirected to another URL and potentially
visiting a malicious actor's site. These can often be chained with other attacks like CSRF to increase the likelihood
of a victim executing an unwanted action. Open redirects can also be used to steal sensitive login information like cookies.

Often, countermeasures involve alerting the user that they are about the leave the site.

* Search for parameters related to redirecting the user like redirect_to
* Search for parameters that include URLs

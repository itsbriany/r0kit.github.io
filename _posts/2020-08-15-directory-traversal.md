---
layout: single
title:  "Bug Hunting Methodology - Directory Traversal"
date:   2020-08-15
excerpt: "My bug hunting methodology on finding directory traversal vulnerabilities in web apps."
categories:
  - bug hunting
  - infosec
tags:
  - directory traversal
---

## Double Url Encoding Bypass

Useful trick in directory traversal/bypass which can sometimes be used to bypass web proxies.

| Value | Url-Encoded | Double Url-Encoded |   |   |
|-------|-------------|--------------------|---|---|
| .     | %2e         | %252e              |   |   |

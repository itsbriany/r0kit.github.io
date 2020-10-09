---
layout: single
title:  "Bug Hunting Methodology - Roadmap"
date:   2020-08-15
excerpt: "My bug hunting roadmap."
categories:
  - bug hunting
  - infosec
tags:
  - roadmap
---

## Where to Start?

* Check out the **Understanding the Organization section below**
* Want to learn more about a specific vulnerability? Go look for it!

## Understanding the Organization 

* One must understand what the organization's most valuable assets are. From here, the bug hunter can figure out which kind of vulnerabilities to prioritize. For example, an XSS on the Twitter feed would be devastating.
* Understanding common patterns and mistakes made by an organization can point you in a direction for certain types of bugs to look for. Chances are, the mistake was a pattern and could be repeated throughout the infrastructure.

## Dependency Monitoring

* Monitor dependencies for web components and understand what they do. This is how a security researcher was able to find a deserializion vulnerability in Groovy. Since Jenkins depended on Groovy which depended on **XStream** (the vulnerable component), Jenkins was suddenly vulnerable to remote code execution. This same concept can also be applied to ruby gems, pip, and node.js modules.
* [Reference](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-2-xstream)

## Finding Deserialization Bugs

* Sometimes, code of the language of choice will deserialize within interesting data structure like YAML or JSON.

## Out of ideas?

* [Bug Bounty Cheatsheet](https://github.com/ngalongc/bug-bounty-reference)

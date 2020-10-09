---
layout: single
title:  "Bug Hunting Methodology - Rate Limiting"
date:   2020-08-15
excerpt: "My bug hunting methodology on finding rate limiting bugs in web apps. Keep in mind, these normally have a lower bounty associated with them."
categories:
  - bug hunting
  - infosec
tags:
  - rate limiting 
---

Rate limiting bugs can have decent impact in some scenarios:

1. Resetting user's password with a guessable value could be brute forced.
2. Attackers could use the server to spam particular users by sending a huge amount of requests, which could impact company reputation. (Email bombing).
3. A user's account could be online-brute forced.

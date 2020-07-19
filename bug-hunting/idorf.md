# IDOR Hunting

## APIs

* Create two accounts.
* Populate as much data as you can for both accounts. Make sure to make at least two instances for each model so that you can test deletion later.
* Streamline the process with Burp's `autorepeater` for this.
* Check for IDOR by computing all the remaining API functions with Burp's `autorize` extension.
* Get lucky, profit!

You might end up finding some models that reference other models that belong to some other identity, and leak the information!

It also helps to create visual tables so you can visualize relationships between data models.

You should prioritize models that have complex relations so you can attempt to disclose indirect information from them.

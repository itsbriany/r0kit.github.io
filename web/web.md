# Web Hacking Notes

## Double Url Encoding Bypass

Useful trick in directory traversal/bypass which can sometimes be used to bypass web proxies.

| Value | Url-Encoded | Double Url-Encoded |   |   |
|-------|-------------|--------------------|---|---|
| .     | %2e         | %252e              |   |   |

## Java Beans XMLDecoder Deserialization

Whenever a backend uses the Java Beans XMLDecoder class, we can deserialize data as code to gain remote code execution.

This is great to check whenever you can submit any sort of XML payload to a Java backend.

* [Cheatsheet](https://gist.github.com/mgeeky/5eb48b17c9d282ad3170ef91cfb6fe4c)

## Finding Deserialization Vulnerabilities in Java Source Code

**Were to find Java deserialization vulnerabilities?**

* Serializable objects are often transported in HTTP heaaders, parameters, and cookies since they essentially represent transportable Java class instances.

**What does a serialized Java object look like?**

* Starts with `AC ED 00 05` or `ro0` in base64.
* `Content-Type` header of an HTTP response is set to `application/x-java-serialized-object`.

**What should you do when you find a Java serialized object?**

* Change its fields and attributes in a way to break authentication, gain remote code execution, or possibly trigger a denial of service.
* Try tampering with file paths to manifest information disclosure.
* Try changing values to alter the application's control flow.

**How can I get remote code execution?**

* Chain gadgets found in libraries loaded by the application.
* The first gadget must be self-executing. Also serach for gadgets in popular libraries e.g. (Commons-Collections, Spring Framework, Groovy, and Apache-Commons Fileupload).

**Searching for gadgets is hard and tedious, is there anything I can do to automate the process?**

* Ysoserial has you covered. It will generate paylaods that exploit Java deserialization vulnerabilities.

**I exploited the vulnerability, how can I fix it?**

* Always validate user input before deserializing it.
* Prefer using a whitelist of classes that are allowed to be deserialized.
* Prefer using simple data types rather than objects.
* If by design, prefer to keep state on the server rather than in cookies since now an attacker could have more control over serialized classes.
* Keep an eye out for patches, and make sure you have a program where you can keep your deployments and dependencies up to date.

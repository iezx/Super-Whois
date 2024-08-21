# Super Whois
域名、IP&ASN WHOIS 查询系统  
支持IDN域名

# 使用方法：
1. 首先选择查询类型"域名 Whois 搜索"或"IP&ASN Whois 搜索"，然后在输入框中输入要查询的域名、IP地址或ASN。
2. 点击提交按钮进行查询。  
3. 查询结果将会显示在下方。
# 注意事项：
部分 Whois 查询结果会显示服务器 IP，请在 "return str_replace"中的 XXX 位置修改服务器 IP，以保护您的服务器 IP 信息。如果查询结果中有服务器 IP 地址，搜索结果中IP地址将会替换成"Super Whois IP Privacy Function"。
```
            $result = array_map(function ($line) {
                return str_replace('XXX', 'Super Whois IP Privacy Function', $line);
            }, $result);
```
## 查询系统外观  
![Super Whois Appearance](https://cdn.807070.xyz/img/new/2024/08/21/7EDyyfHMx9.png)
    
# Super Whois
Domain Name, IP&ASN WHOIS Search System  
Support IDN domain name

# Method of Use: 
1. First, select the query type "Domain Whois Search" or "IP&ASN Whois Search", and then enter the domain name, IP address or ASN to be queried in the input box.
2. Click on the Enquiry button.
3. The result will be displayed below.

# Please Note:
Some Whois query results will show server IP, please change the server IP in the XXX position in "return str_replace" to protect your server IP information. If there is a server IP address in the query result, the IP address in the search result will be replaced with "Super Whois IP Privacy Function".
```
            $result = array_map(function ($line) {
                return str_replace('XXX', 'Super Whois IP Privacy Function', $line);
            }, $result);
```
## Super Whois Appearance  
![Super Whois Appearance](https://cdn.807070.xyz/img/new/2024/08/21/7EDyyfHMx9.png)




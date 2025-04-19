# Super Whois
域名、IP&ASN WHOIS 查询系统  
支持IDN域名

# 使用方法：
1. 在输入框中输入要查询的域名、IP地址或ASN。
2. 点击提交按钮或回车进行查询。  
3. 查询结果将会显示。
# 注意事项：
部分 Whois 查询结果会显示服务器 IP，请在 "return str_replace"中的 XXX 位置修改服务器 IP，以保护您的服务器 IP 信息。如果查询结果中有服务器 IP 地址，搜索结果中IP地址将会替换成"Super Whois IP Privacy Function"。
```
            $result = array_map(function ($line) {
                return str_replace('XXX', 'Super Whois IP Privacy Function', $line);
            }, $result);
```
## 查询系统外观  
![Super Whois Appearance](https://cdn.807070.xyz/img/new/2025/04/19/1u583s8SU0.png)
    
# Super Whois
Domain Name, IP&ASN WHOIS Search System  
Support IDN domain name

# How to Use: 
1. Enter the domain name, IP address, or ASN in the input field.
2. Click the submit button or press enter to enquire and get the results.
3. The query result will be displayed.

# Please Note:
Some Whois query results will show server IP, please change the server IP in the XXX position in "return str_replace" to protect your server IP information. If there is a server IP address in the query result, the IP address in the search result will be replaced with "Super Whois IP Privacy Function".
```
            $result = array_map(function ($line) {
                return str_replace('XXX', 'Super Whois IP Privacy Function', $line);
            }, $result);
```
## Super Whois Appearance  
![Super Whois Appearance](https://cdn.807070.xyz/img/new/2025/04/19/1u583s8SU0.png)




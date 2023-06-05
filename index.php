<!DOCTYPE html>
<html>
<head>
    <title>Domain Name, IP WHOIS Search</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Welcome to Domain Name, IP WHOIS Search. You can check domain whois and ipv4 ipv6 whois." />
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
</head>
<body>
    <h1>Domain Name, IP WHOIS Search System</h1>
    <form method="post" action="">
    <input type="text" name="query" placeholder="Please enter!" onblur="removeSpaces(this)" required>
        <select name="type">
            <option value="whois" <?php if($_POST['type'] == 'whois') echo 'selected'; ?>>Domain WHOIS Search</option>
            <option value="ipwhois" <?php if($_POST['type'] == 'ipwhois') echo 'selected'; ?>>IP WHOIS Search</option>
            <option value="ns" <?php if($_POST['type'] == 'ns') echo 'selected'; ?>>Domain NS Search</option>
        </select>
        <input type="submit" name="submit" value="Enquiry">
    </form>

    <?php
    //V1.0.1 支持空格判断，在提交表单之前自动去除输入中的空格

    error_reporting(0); // 禁用错误报告

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
        $query = $_POST['query'];
        $type = $_POST['type'];

        switch ($type) {
            case 'whois':
                performWhoisQuery($query);
                break;
            case 'ipwhois':
                performIPWhoisQuery($query);
                break;
            case 'ns':
                performNSQuery($query);
                break;
        }
    }
    // 执行 WHOIS 查询
    function performWhoisQuery($domain) {
        require_once __DIR__ . '/whois_servers.php';
        $extension = getDomainExtension($domain);

        if (isset($whoisServers[$extension])) {
            $server = $whoisServers[$extension];
            $result = queryWhoisServer($server, $domain);

            echo '<div class="result">';
            if (!empty($result)) {
                echo '<h2>' . $domain . ' WHOIS information</h2>';
                echo '<p>Searched from: ' . $server . '</p>';
                echo '<ul>';
                foreach ($result as $line) {
                    echo '<li>' . $line . '</li>';
                }
                echo '</ul>';
            } else {
                echo '<h2>Unable to find WHOiS information of the domain name: The domain name may not be registered or the server is not searched.</h2>';
            }
            echo '</div>';
        } else {
            echo '<div class="result">';
            echo '<h2>WHOIS search for this domain name is not supported.</h2>';
            echo '</div>';
        }
    }
    // 执行 IP WHOIS 查询
    function performIPWhoisQuery($ip) {
        $server = 'whois.apnic.net';
        $result = queryWhoisServer($server, $ip);

        echo '<div class="result">';
        if (!empty($result)) {
            echo '<h2>' . $ip . ' WHOIS information</h2>';
            echo '<p>Searched from: ' . $server . '</p>';
            echo '<ul>';
            foreach ($result as $line) {
                echo '<li>' . $line . '</li>';
            }
            echo '</ul>';
        } else {
            echo '<h2>IP WHOIS information not available.</h2>';
        }
        echo '</div>';
    }
    // 执行 NS 查询
    function performNSQuery($domain) { 
        $result = getNSRecords($domain);
    
        echo '<div class="result">';
        if (!empty($result)) {
            echo '<h2>' . $domain . ' NS information</h2>';
            echo '<ul>';
            foreach ($result as $record) {
                echo '<li>' . $record . '</li>';
            }
            echo '</ul>';
        } else {
            echo '<h2>NS information not available: The domain name may not be registered or the server may not be searched.</h2>';
        }
        echo '</div>';
    }
    
    function getNSRecords($domain) {
        $result = array();
        $output = @dns_get_record($domain, DNS_NS);
        if (!empty($output)) {
            foreach ($output as $record) {
                $result[] = $record['target'];
            }
        }
        return $result;
    }
    
    // 获取域名后缀
    function getDomainExtension($domain) {
        $parts = explode('.', $domain);
        $extension = end($parts);
        return strtolower($extension);
    }
    // 查询 WHOIS 服务器
    function queryWhoisServer($server, $query) {
        $result = array();
        $fp = @fsockopen($server, 43, $errno, $errstr, 10);
        if ($fp) {
            fputs($fp, $query . "\r\n");
            while (!feof($fp)) {
                $result[] = fgets($fp);
            }
            fclose($fp);
        }
        return $result;
    }

    ?>
</body>
<script>
function removeSpaces(input) {
  input.value = input.value.replace(/\s+/g, ''); // 空格去除判断
}
</script>
<!--https://github.com/iezx/Super-Whois-->
</html>

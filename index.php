<!DOCTYPE html>
<html lang="en">
<head>
    <title>Super Whois</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Welcome to Domain Name, IP WHOIS Search. You can check domain whois and ipv4 ipv6 whois." />
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h1>Domain Name, IP WHOIS Search System</h1>
    <form method="post" action="">
        <input type="text" name="query" placeholder="Please enter and press Enquiry." required value="<?php echo isset($_POST['query']) ? removeSpaces($_POST['query']) : ''; ?>">
        <select name="type">
        <?php
        $options = [
            'whois' => 'Domain WHOIS Search',
            'ipwhois' => 'IP WHOIS Search',
            'ns' => 'Domain NS Search'
        ];

        foreach ($options as $value => $label) {
            $selected = (isset($_POST['type']) && $_POST['type'] === $value) ? 'selected' : '';
            echo '<option value="' . $value . '" ' . $selected . '>' . $label . '</option>';
        }
        ?>
        </select>
        <input type="submit" name="submit" value="Enquiry">
    </form>
    
    <?php
    //v1.0.5  1.优化搜索代码 2.更新空格判断代码

    //error_reporting(0); // 禁用错误报告代码

    // 去除输入域名中的所有空格
    function removeSpaces($input) {
        return preg_replace('/\s+/', '', $input);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
        $query = removeSpaces($_POST['query']);
        $type = $_POST['type'];

        $query = idn_to_ascii($query);

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
                echo '<h2>' . $domain . ' WHOIS Information</h2>';
                echo '<p>Searched from: ' . $server . '</p>'; // 输出Whois服务器
                echo '<ul>';
                foreach ($result as $line) {
                    echo '<li>' . $line . '</li>';
                }
                echo '</ul>';
            } else {
                echo '<h2>Unable to find WHOIS information for the domain name. The domain name may not be registered or the server is not accessible.</h2>';
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
<footer>
    <p><a href="https://github.com/iezx/Super-Whois" target="_blank">Super Whois</a> Version 1.0.5</p>
</footer>
</html>

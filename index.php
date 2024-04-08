<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Super Whois</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Welcome to Domain Name, IP&ASN WHOIS Search. You can check domain whois and ipv4 ipv6 whois." />
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
    <h1>Domain Name, IP&ASN WHOIS Search System</h1>
    <form method="post" action="">
        <input type="text" name="query" placeholder="Please enter and press Enquiry." required value="<?php echo isset($_POST['query']) ? htmlspecialchars(removeSpaces($_POST['query']), ENT_QUOTES, 'UTF-8') : ''; ?>">
        <select name="type">
            <?php
            $options = [
                'whois' => 'Domain WHOIS Search',
                'ipwhois' => 'IP&ASN WHOIS Search',
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
    // v1.1.0 1.优化CSS 2.更新和优化代码 2.1.优化判断域名是否已注册 2.2.执行 WHOIS 查询部分代码 3.添加支持ASN查询

    // error_reporting(0); // 禁用错误报告代码 

    // 去除输入域名中的所有空格
    function removeSpaces($input)
    {
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
        }
    }

    // 执行 WHOIS 查询
    function performWhoisQuery($domain)
    {
        require_once __DIR__ . '/whois_servers.php';
        $extension = getDomainExtension($domain);

        if (isset($whoisServers[$extension])) {
            $server = $whoisServers[$extension];
            $result = queryWhoisServer($server, $domain);

            $isRegistered = isDomainRegistered($result);
            $currentDate = date('Y-m-d'); // 获取当前日期
            // 追踪是否已输出注册商信息
            $hasRegistrarInfo = false;
            echo '<div class="result">';
            if (!empty($result)) {
                echo '<h2>' . $domain . ' WHOIS Information</h2>';
                echo '<div class="info-container">';
                echo '<p>Searched from: ' . $server . '</p>';
                echo '<p>Domain Registration: ' . ($isRegistered ? 'Registered' : 'Unregistered') . '</p>';
                echo '<p>Reserved domain name: ' . (isDomainReserved($result) ? 'Reserved' : 'Not Reserved') . '&nbsp;(Only Reference)' . '</p>';
                echo '<p>Current Date: ' . $currentDate . '</p>';

                // 获取并输出主要信息
                foreach ($result as $line) {
                    // 判断是否包含到期日期信息
                    if (strpos($line, 'Expiration Date') !== false || strpos($line, 'Registrar Registration Expiration Date') !== false || strpos($line, 'Registry Expiry Date') !== false || strpos($line, 'Expiry Date:') !== false || strpos($line, 'Expiration Time:') !== false) {
                        // 输出到期日期
                        echo '<p>Expiration Date: ' . trim(str_replace(['Expiration Date:', 'Registrar Registration Expiration Date:', 'Registry Expiry Date:', 'Expiry Date:', 'Expiration Time:'], '', $line)) . '</p>';
                    }
                    // 判断是否包含注册日期信息
                    elseif (strpos($line, 'Creation Date') !== false || strpos($line, 'Domain Registration Date') !== false || strpos($line, 'created:') !== false || strpos($line, 'Registration Time:') !== false) {
                        // 输出注册日期
                        echo '<p>Registration Date: ' . trim(str_replace(['Creation Date:', 'Domain Registration Date:', 'created:', 'Registration Time:'], '', $line)) . '</p>';
                    }
                    // 判断是否包含更新日期信息
                    elseif (strpos($line, 'Updated Date') !== false || strpos($line, 'Last Updated') !== false || strpos($line, 'last-update:') !== false) {
                        // 输出更新日期
                        echo '<p>Last Updated Date: ' . trim(str_replace(['Updated Date:', 'Last Updated:', 'last-update:'], '', $line)) . '</p>';
                    }
                    // 判断是否包含 NS 服务器信息
                    elseif (strpos($line, 'Name Server') !== false || strpos($line, 'Name Servers') !== false || strpos($line, 'NS') !== false || strpos($line, 'nserver:') !== false) {
                        // 输出 NS 服务器信息
                        echo '<p>DNS: ' . trim(str_replace(['Name Server:', 'Name Servers:', 'NS:', 'nserver:'], '', $line)) . '</p>';
                    }

                    // 判断是否包含注册人信息
                    elseif (strpos($line, 'Registrant:') !== false || strpos($line, 'Registrant Name:') !== false || strpos($line, 'Registrant Organization:') !== false) {
                        // 输出注册人信息
                        echo '<p>Registrant: ' . trim(str_replace(['Registrant:', 'Registrant Name:', 'Registrant Organization:'], '', $line)) . '</p>';
                    }
                    // 判断是否包含注册人邮箱
                    elseif (strpos($line, 'Registrant Email') !== false) {
                        // 输出注册人邮箱
                        echo '<p>Registrant Email: ' . trim(str_replace('Registrant Email:', '', $line)) . '</p>';
                    }

                    // 判断是否包含注册商信息
                    elseif (!$hasRegistrarInfo && (strpos($line, 'Registrar:') !== false || strpos($line, 'Registrar WHOIS Server') !== false || strpos($line, 'registrar:') !== false)) {
                        // 输出注册商信息
                        echo '<p>Registrar: ' . trim(str_replace(['Registrar:', 'Registrar WHOIS Server:', 'registrar:'], '', $line)) . '</p>';

                        // 将 $hasRegistrarInfo 设置为 true，确保只输出一次注册商信息
                        $hasRegistrarInfo = true;
                    }
                    // 判断是否包含域名状态信息
                    elseif (strpos($line, 'Status:') !== false) {
                        // 输出域名状态信息
                        echo '<p>Status: ' . trim(str_replace('Status:', '', $line)) . '</p>';
                    }
                }


                echo '</div>';
                echo '<h3 class="details-toggle" onclick="toggleDetails()">Show Details</h3>';
                echo '<div class="details-content" id="details-content">';
                echo '<div class="info-container">';
                echo '<ul>';
                foreach ($result as $line) {
                    echo '<li>' . $line . '</li>';
                }
                echo '</ul>';
                echo '</div>';
                echo '</div>';
            } else {
                echo '<h3>WHOIS information for the domain name could not be found. The domain name may not be registered or the domain Whois server is not accessible.</h3>';
            }
            echo '</div>';
        } else {
            echo '<div class="result">';
            echo '<h3>WHOIS search for this domain name is not supported.</h3>';
            echo '</div>';
        }
    }

    // 执行 IP AS WHOIS 查询
    function performIPWhoisQuery($ip)
    {
        $server = 'whois.apnic.net';
        $server = 'WHOIS.ARIN.NET';
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

    // 获取域名后缀
    function getDomainExtension($domain)
    {
        $parts = explode('.', $domain);
        $extension = end($parts);
        return strtolower($extension);
    }

    // 查询 WHOIS 服务器
    function queryWhoisServer($server, $query)
    {
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

    // 判断域名是否保留
    function isDomainReserved($whoisResult)
    {
        $reservedKeywords = array('reserved', '保留域名', 'reserved domain name', '保留', 'keep', 'clientHold', 'serverHold');

        foreach ($whoisResult as $line) {
            foreach ($reservedKeywords as $keyword) {
                if (stripos($line, $keyword) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    // 判断域名是否已注册
    function isDomainRegistered($whoisResult)
    {
        $registeredKeywords = array(
            'Registrar:',
            'Creation Date:',
            'Domain Name:',
            'Registry Domain ID:',
            'connect',
            'Status: connect',
            'Status: active',
        );

        $hasNSInfo = false;

        foreach ($whoisResult as $line) {
            foreach ($registeredKeywords as $keyword) {
                if (stripos($line, $keyword) !== false) {
                    return true;
                }
            }

            if (preg_match('/^\s*Name\s+Server:/i', $line) || preg_match('/^\s*Name\s+Servers:/i', $line) || preg_match('/^\s*NS:/i', $line) || preg_match('/^\s*nserver:\s+/i', $line)) {
                $hasNSInfo = true;
            }
        }

        return $hasNSInfo;
    }
    ?>
</body>
<footer>
    <p><a href="https://github.com/iezx/Super-Whois" target="_blank">Super Whois</a> Version 1.1.0 </p>        
</footer>
<script>
    function toggleDetails() {
        var detailsContent = document.getElementById('details-content');
        var detailsToggle = document.querySelector('.details-toggle');

        if (detailsContent.style.display === 'none') {
            detailsContent.style.display = 'block';
            detailsToggle.classList.add('open');
        } else {
            detailsContent.style.display = 'none';
            detailsToggle.classList.remove('open');
        }
    }
</script>
</html>
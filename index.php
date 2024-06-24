<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Super Whois</title>
    <link rel="stylesheet" type="text/css" href="style.css">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Welcome to use domain name, IP&ASN WHOIS search system to query domain name information. You can check domain whois, ipv4, ipv6 and ASN whois information." />
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

    <div class="illustrate" id="englishGuide">

        <h4><a href="#" onclick="toggleLanguage('chinese')">中文说明</a></h4>
        <h3>Welcome to the Domain Name, IP&amp;ASN WHOIS Search System!</h3>
        <p>You can use this tool to query domain name information, IP addresses, and ASN information. Simply enter the domain name, IP address, or ASN number in the input field above and select the appropriate search type (Domain WHOIS Search or IP&amp;ASN WHOIS Search).</p>

        <h2>How to Use:</h2>
        <ol>
            <li>Enter the domain name, IP address, or ASN number in the input field.</li>
            <li>Select the appropriate search type (Domain or IP&amp;ASN WHOIS Search).</li>
            <li>Click the "Enquiry" button to get the results.</li>
            <li>After submitting your query, you will see detailed WHOIS information for the specified domain name, IP address, or ASN number.</li>
        </ol>

        <h2>Results:</h2>
        <p>The results include registration details, expiration date, registrar information, DNS servers, and more.</p>
        <h2>Domain Examples:</h2>
        <p>Domain Name (Example: example.com)</p>
        <p>IDN Domain Name (Example: 你好.世界)</p>
        <h2>ASN Examples:</h2>
        <p>ASN 16bit (Example: AS15169)</p>
        <p>ASN 32bit (Example: AS401308)</p>
        <h2>IP Examples:</h2>
        <p>IPv4 (Example: 8.8.8.8)</p>
        <p>IPv6 (Example: 2400:3200::1)</p>
        <h4>Searching ASN/IPv4/IPv6 may take longer time, if timeout, please retry.</h4>
    </div>

    <div class="illustrate" id="chineseGuide" style="display: none;">
        <h4><a href="#" onclick="toggleLanguage('english')">English</a></h4>
        <h3>欢迎使用域名、IP和ASN WHOIS查询系统！</h3>
        <p>您可以使用此工具查询域名信息、IP地址和ASN信息。只需在上方的输入框中输入域名、IP地址或ASN号码，并选择适当的搜索类型（域名WHOIS搜索或IP&ASN WHOIS搜索）。</p>
        <h2>使用方法：</h2>
        <ol>
            <li>在输入框中输入域名、IP地址或ASN号码。</li>
            <li>选择适当的搜索类型（域名或IP&ASN WHOIS搜索）。</li>
            <li>点击"查询"按钮以获取结果。</li>
            <li>提交查询后，您将看到指定域名、IP地址或ASN号码的详细WHOIS信息。</li>
        </ol>
        <h2>域名示例：</h2>
        <p>域名（示例：example.com）</p>
        <p>IDN 域名（示例：你好.世界）</p>
        <h2>ASN 示例：</h2>
        <p>ASN 16bit（示例：AS15169）</p>
        <p>ASN 32bit（示例：AS401308）</p>
        <h2>IP 示例：</h2>
        <p>IPv4（示例：8.8.8.8）</p>
        <p>IPv6（示例：2400:3200::1）</p>
        <h4>搜索 ASN/IPv4/IPv6 可能需要花费更长时间，如果超时，请重试。</h4>
    </div>



    <?php
    // v1.1.1 1.替换ip地址 (在return str_replace输入服务器IP) 部分whois会显示服务器IP 2.使用正则表达式来提取主要信息 3.增加使用说明 4.优化获取输出主要信息的代码
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
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {

        // 隐藏illustrate区域
        echo '<style>.illustrate { display: none; }</style>';
    }
    // 执行 WHOIS 查询
    function performWhoisQuery($domain)
    {
        require_once __DIR__ . '/whois_servers.php';
        $extension = getDomainExtension($domain);

        if (isset($whoisServers[$extension])) {
            $server = $whoisServers[$extension];
            $result = queryWhoisServer($server, $domain);

            // 替换ip地址为IP privacy service provided by Super Whois 在XXX输入你服务器IP Enter your server IP in XXX
            $result = array_map(function ($line) {
                return str_replace('XXX', 'Super Whois IP Privacy Function', $line);
            }, $result);

            $isRegistered = isDomainRegistered($result);
            $currentDate = date('Y-m-d'); // 获取当前日期
            $outputtedInfo = []; // 存储已输出的信息

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
                $whoisDetails = [
                    'Expiration Date' => 'Expiration Date',
                    'Registrar Registration Expiration Date' => 'Expiration Date',
                    'Registry Expiry Date' => 'Expiration Date',
                    'Expiry Date:' => 'Expiration Date',
                    'Expiration Time:' => 'Expiration Date',
                    'expires' => 'Expiration Date',
                    'Creation Date' => 'Registration Date',
                    'Domain Registration Date' => 'Registration Date',
                    'created' => 'Registration Date',
                    'Registration Time:' => 'Registration Date',
                    'Updated Date' => 'Last Updated Date',
                    'Last Updated' => 'Last Updated Date',
                    'last-update:' => 'Last Updated Date',
                    'modified' => 'Last Updated Date',
                    'Name Server' => 'DNS',
                    'Name Servers' => 'DNS',
                    'NS' => 'DNS',
                    'nserver:' => 'DNS',
                    'DNSSEC' => 'DNSSEC',
                    'Registrant:' => 'Registrant',
                    'Registrant Name:' => 'Registrant',
                    'Registrant Organization:' => 'Registrant',
                    'Registrant Email' => 'Registrant Email',
                    'Registrar:' => 'Registrar',
                    'Registrar WHOIS Server' => 'Registrar',
                    'registrar:' => 'Registrar',
                    'Status' => 'Domain Status',
                    'Domain Status' => 'Domain Status',
                    'DNSSEC:' => 'DNSSEC',

                ];

                foreach ($result as $line) {
                    foreach ($whoisDetails as $keyword => $infoType) {
                        // 使用精确匹配避免误识别
                        if (preg_match('/^\s*' . preg_quote($keyword, '/') . '\s*(.*)$/i', $line, $matches)) {
                            $value = trim($matches[1]);
                            if (!isset($outputtedInfo[$infoType])) {
                                $outputtedInfo[$infoType] = [];
                            }
                            if (!in_array($value, $outputtedInfo[$infoType])) {
                                echo '<p>' . $infoType . ': ' . ltrim($value, ': ') . '</p>';
                                $outputtedInfo[$infoType][] = $value; // 添加到已输出列表
                            }
                            break;
                        }
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
    <p><a href="https://github.com/iezx/Super-Whois" target="_blank">Super Whois</a> Version 1.1.1 </p>
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
<script>
    function toggleLanguage(language) {
        if (language === 'english') {
            document.getElementById('englishGuide').style.display = 'block';
            document.getElementById('chineseGuide').style.display = 'none';
        } else if (language === 'chinese') {
            document.getElementById('englishGuide').style.display = 'none';
            document.getElementById('chineseGuide').style.display = 'block';
        }
    }
</script>

</html>

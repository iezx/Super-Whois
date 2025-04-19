<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Super Whois</title>
    <link rel="stylesheet" type="text/css" href="./style.css">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="Welcome to use domain name, IP&ASN WHOIS search system to query domain name information. You can check domain whois, ipv4, ipv6 and ASN whois information." />
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
    <header>
        <h2>Domain Name, IP&ASN WHOIS Search System</h2>
    </header>
    <main>
        <div class="illustrate">
            <p> <strong>说明：</strong> 本系统支持域名、IP、ASN的Whois信息查询。请在搜索框中输入，点击搜索按钮即可查询相关信息。</p>
            <p> <strong>Instruction:</strong> You can use this tool to find domain name information, IP address, and ASN information. Simply enter the domain name, IP address, or ASN in the input box.</>
        </div>
        <div class="form-container">
            <form method="post" action="">
                <div class="form-group">
                    <input type="text" name="query" placeholder="Enter information" required
                        value="<?php echo isset($_POST['query']) ? htmlspecialchars(removeSpaces($_POST['query']), ENT_QUOTES, 'UTF-8') : ''; ?>">
                </div>
                <button type="submit" name="submit" class="submit-button">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </button>
            </form>

            <?php
            // v1.1.2  1.全面优化CSS样式 2.新增查询记录

            // 去除输入域名中的所有空格
            function removeSpaces($input)
            {
                return preg_replace('/\s+/', '', $input);
            }

            function getDomainExtension($domain)
            {
                // 确保是ASCII 形式
                $domainAscii = idn_to_ascii($domain);
                $parts = explode('.', $domainAscii);
                return strtolower(end($parts));
            }

            if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit'])) {
                $query = removeSpaces($_POST['query']);
                $query = idn_to_ascii($query);

                /*//调试信息
            echo '<div class="result"><p>Processed Query: ' . htmlspecialchars($query, ENT_QUOTES, 'UTF-8') . '</p></div>'; */

                if (filter_var($query, FILTER_VALIDATE_IP)) {
                    performIPWhoisQuery($query);
                } elseif (preg_match('/^AS\d+$/i', $query)) {
                    performASNWhoisQuery($query);
                } elseif (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}|^xn--[a-z0-9]+\.xn--[a-z0-9]+$/i', $query)) {
                    performWhoisQuery($query);
                } else {
                    echo '<div class="result"><h3>Invalid query. Please enter a valid domain, IP, or ASN.</h3></div>';
                }
            }


            // 执行 WHOIS 查询
            function performWhoisQuery($domain)
            {
                require_once __DIR__ . '/whois_servers.php';

                $domainAscii = idn_to_ascii($domain);
                $extension = getDomainExtension($domainAscii);

                if (isset($whoisServers[$extension])) {
                    $server = $whoisServers[$extension];
                    $result = queryWhoisServer($server, $domainAscii);
                    // Protect server IP information 保护服务器IP信息
                    $result = array_map(function ($line) {
                        return str_replace('Enter your IP', 'Super Whois IP Privacy Function', $line);
                    }, $result);

                    $isRegistered = isDomainRegistered($result);
                    $currentDate = date('Y-m-d');
                    $outputtedInfo = [];

                    $hasRegistrarInfo = false;
                    echo '<div class="result">';
                    if (!empty($result)) {
                        echo '<h2>' . htmlspecialchars($domain) . ' WHOIS Information</h2>';
                        echo '<div class="info-container">';
                        echo '<p>Searched from: ' . htmlspecialchars($server) . '</p>';
                        echo '<p>Domain Registration: ' . ($isRegistered ? 'Registered' : 'Unregistered') . '</p>';
                        echo '<p>Reserved domain name: ' . (isDomainReserved($result) ? 'Reserved' : 'Not Reserved') . '&nbsp;(Only Reference)' . '</p>';
                        echo '<p>Current Date: ' . $currentDate . '</p>';

                        $whoisDetails = [
                            'Expiration Date' => 'Expiration Date',
                            'Registrar Registration Expiration Date' => 'Expiration Date',
                            'Registry Expiry Date' => 'Expiration Date',
                            'Expiry Date:' => 'Expiration Date',
                            'Expiration Time:' => 'Expiration Date',
                            'expires' => 'Expiration Date',
                            'Record expires on' => 'Expiration Date',
                            'Creation Date' => 'Registration Date',
                            'Domain Registration Date' => 'Registration Date',
                            'Domain Name Commencement Date' => 'Registration Date',
                            'created' => 'Registration Date',
                            'Record created' => 'Registration Date',
                            'Registration Time:' => 'Registration Date',
                            'Updated Date on' => 'Last Updated Date',
                            'Updated Date' => 'Last Updated Date',
                            'last-update'  => 'Last Updated Date',
                            'Record last updated on' => 'Last Updated Date',
                            'Last Updated' => 'Last Updated Date',
                            'modified' => 'Last Updated Date',
                            'Name Server' => 'DNS',
                            'Name Servers' => 'DNS',
                            'Domain nameservers' => 'DNS',
                            'NS:' => 'DNS',
                            'Name Servers Information:' => 'DNS',
                            'nserver' => 'DNS',
                            'DNSSEC' => 'DNSSEC',
                            'Registrant:' => 'Registrant',
                            'Registrant Name:' => 'Registrant',
                            'Registrant Organization:' => 'Registrant',
                            'Registrant Email' => 'Registrant Email',
                            'Registrant Contact Email' => 'Registrant Email',
                            'Given Name:' => 'Given Name',
                            'Family Name' => 'Family Name',
                            'Registrar WHOIS Server' => 'Registrar',
                            'registrar:' => 'Registrar',
                            'Registrar Name' => 'Registrar',
                            'Sponsoring Registrar' => 'Registrar',
                            'Status' => 'Domain Status',
                            'Status Information' => 'Status Information',
                            'Domain Status' => 'Domain Status',
                            'DNSSEC:' => 'DNSSEC',
                            'Bundled Domain Name' => 'Bundled Domain Name',
                            'Country' => 'Country/Region',
                            'Region' => 'Country/Region',
                            'Address' => 'Address',
                            // 日文关键词
                            '[登録者]' => 'Registrant',
                            '[登録年月日]' => 'Registration Date',
                            '[有効期限]' => 'Expiration Date',
                            '[最終更新]' => 'Last Updated Date',
                            '[ネームサーバー]' => 'DNS',
                            '[登録担当者]' => 'Registrant Contact',
                            '[組織名]' => 'Registrant Organization',
                            '[都道府県]' => 'Prefecture',
                            '[国]' => 'Country/Region',
                            '[状態]' => 'Domain Status',
                            'Domain nameservers' => 'DNS',
                            'NS:' => 'DNS',
                            'Name Servers Information:' => 'DNS',
                            'nserver' => 'DNS',
                            'DNSSEC' => 'DNSSEC',
                            'Registrant:' => 'Registrant',
                            'Registrant Name:' => 'Registrant',
                            'Registrant Organization:' => 'Registrant',
                            'Registrant Email' => 'Registrant Email',
                            'Registrant Contact Email' => 'Registrant Email',
                            'Given Name:' => 'Given Name',
                            'Family Name' => 'Family Name',
                            'Registrar WHOIS Server' => 'Registrar',
                            'registrar:' => 'Registrar',
                            'Registrar Name' => 'Registrar',
                            'Sponsoring Registrar' => 'Registrar',
                            'Status' => 'Domain Status',
                            'Status Information' => 'Status Information',
                            'Domain Status' => 'Domain Status',
                            'DNSSEC:' => 'DNSSEC',
                            'Bundled Domain Name' => 'Bundled Domain Name',
                            'Country' => 'Country/Region',
                            'Region' => 'Country/Region',
                            'Address' => 'Address',
                        ];

                        $dnsRecords = [];
                        $collectingDns = false;
                        foreach ($result as $line) {
                            $trimmedLine = trim($line);
                            // 检查是否为DNS相关字段的起始行
                            $dnsStart = false;
                            foreach (
                                [
                                    'Name Server',
                                    'Name Servers',
                                    'Domain nameservers',
                                    'NS:',
                                    'Name Servers Information:',
                                    'nserver',
                                    '[ネームサーバー]'
                                ] as $dnsKey
                            ) {
                                if (preg_match('/^\s*' . preg_quote($dnsKey, '/') . '\s*:?(.*)$/i', $line, $matches)) {
                                    $dnsStart = true;
                                    $value = trim($matches[1]);
                                    if ($value !== '') {
                                        if (!in_array($value, $dnsRecords)) {
                                            $dnsRecords[] = $value;
                                        }
                                    }
                                    $collectingDns = true;
                                    break;
                                }
                            }
                            if ($dnsStart) {
                                continue;
                            }
                            // 如果正在收集DNS且当前行非空且不是其他字段，则继续收集
                            if ($collectingDns && $trimmedLine !== '' && !preg_match('/^[A-Za-z0-9\[\] _\-]+:/', $trimmedLine)) {
                                if (!in_array($trimmedLine, $dnsRecords)) {
                                    $dnsRecords[] = $trimmedLine;
                                }
                                continue;
                            } else {
                                $collectingDns = false;
                            }
                            foreach ($whoisDetails as $keyword => $infoType) {
                                if (preg_match('/^\s*' . preg_quote($keyword, '/') . '\s*(.*)$/i', $line, $matches)) {
                                    $value = trim($matches[1]);
                                    if ($infoType === 'DNS') {
                                        // 已由上方逻辑处理
                                        break;
                                    }
                                    if (!isset($outputtedInfo[$infoType])) {
                                        $outputtedInfo[$infoType] = [];
                                    }
                                    if (!in_array($value, $outputtedInfo[$infoType])) {
                                        echo '<p>' . $infoType . ': ' . ltrim($value, ': ') . '</p>';
                                        $outputtedInfo[$infoType][] = $value;
                                    }
                                    break;
                                }
                            }
                        }
                        // 在此处输出一次所有收集到的DNS记录
                        if (!empty($dnsRecords)) {
                            echo '<p>DNS: ' . implode('<br>', array_map('ltrim', $dnsRecords)) . '</p>';
                        }
                        echo '</div>';
                        echo '<h3 class="details-toggle" onclick="toggleDetails()">Show Details</h3>';
                        echo '<div class="details-content" id="details-content">';
                        echo '<div class="info-container">';
                        echo '<ul>';
                        foreach ($result as $line) {
                            echo '<li>' . htmlspecialchars($line) . '</li>';
                        }
                        echo '</ul>';
                        echo '</div>';
                        echo '</div>';
                    } else {
                        echo '<h3>WHOIS information for the domain name could not be found.</h3>';
                    }
                    echo '</div>';
                } else {
                    echo '<div class="result">';
                    echo '<h3>WHOIS search for this domain name is not supported.</h3>';
                    echo '</div>';
                }
            }

            // 执行 IP WHOIS 查询
            function performIPWhoisQuery($ip)
            {
                $server = 'whois.apnic.net'; // 选择适当的 WHOIS 服务器
                $result = queryWhoisServer($server, $ip);

                echo '<div class="result">';
                if (!empty($result)) {
                    echo '<h2>' . htmlspecialchars($ip) . ' WHOIS information</h2>';
                    echo '<p>Searched from: ' . htmlspecialchars($server) . '</p>';
                    echo '<div class="info-container">';
                    echo '<ul>';
                    foreach ($result as $line) {
                        echo '<li>' . htmlspecialchars($line) . '</li>';
                    }
                    echo '</ul>';
                    echo '</div>';
                } else {
                    echo '<h3>WHOIS information for the IP address could not be found.</h3>';
                }
                echo '</div>';
            }

            // 执行 ASN WHOIS 查询
            function performASNWhoisQuery($asn)
            {
                $server = 'whois.arin.net'; // 选择适当的 WHOIS 服务器
                $result = queryWhoisServer($server, $asn);

                echo '<div class="result">';
                if (!empty($result)) {
                    echo '<h2>' . htmlspecialchars($asn) . ' WHOIS information</h2>';
                    echo '<p>Searched from: ' . htmlspecialchars($server) . '</p>';
                    echo '<div class="info-container">';
                    echo '<ul>';
                    foreach ($result as $line) {
                        echo '<li>' . htmlspecialchars($line) . '</li>';
                    }
                    echo '</ul>';
                    echo '</div>';
                } else {
                    echo '<h3>WHOIS information for the ASN could not be found.</h3>';
                }
                echo '</div>';
            }

            function queryWhoisServer($server, $query)
            {
                $whois = fsockopen($server, 43, $errno, $errstr, 10);
                if (!$whois) {
                    return [];
                }

                fwrite($whois, $query . "\r\n");
                $response = '';
                while (!feof($whois)) {
                    $response .= fgets($whois, 128);
                }
                fclose($whois);

                return explode("\n", $response);
            }

            function isDomainRegistered($result) //域名注册检测
            {
                foreach ($result as $line) {
                    if (
                        stripos($line, 'Domain Status:') !== false ||
                        stripos($line, 'Registrar:') !== false ||
                        stripos($line, 'Creation Date:') !== false ||
                        stripos($line, 'Active') !== false
                    ) {
                        return true;
                    }
                }
                return false;
            }


            function isDomainReserved($result) //域名保留检测
            {
                foreach ($result as $line) {
                    if (stripos($line, 'Reserved') !== false) {
                        return true;
                    }
                }
                return false;
            }

            ?>
            <div class="history-container">
                <h3>查询记录 Records</h3>
                <p>历史记录存储在本地，最多20条记录。</p>
                <p>History stored locally, up to 20 records.</p>
                <button class="h_clear"onclick="clearHistory()"><p>清除记录 Clear Records</p></button>
                <br>
                <ul id="history-list"></ul>
            </div>

            <script>
                function clearHistory() {
                    localStorage.removeItem(historyKey);
                    loadHistory();
                }
            </script>
            <div class="illustrate" id="englishGuide">

                <h4><a href="#" onclick="toggleLanguage('chinese')">中文说明</a></h4>
                <h3>Welcome to the Domain Name, IP&amp;ASN WHOIS Search System!</h3>
                <p>You can use this tool to find domain name information, IP address, and ASN information. Simply enter the domain name, IP address, or ASN in the input box.</p>

                <h2>How to Use:</h2>
                <ol>
                    <li>Enter the domain name, IP address or ASN to be queried in the input box.</li>
                    <li>Click the submit button or press enter to enquire and get the results.</li>
                    <li>After submitting your query, you will see detailed WHOIS information for the domain name, IP address or ASN.</li>
                </ol>

                <h2>Results:</h2>
                <p>The results include registration details, expiration date, registrar information, DNS servers, and
                    more.</p>
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
                <p>您可以使用此工具查询域名信息、IP地址和ASN信息。只需在上方的输入框中输入域名、IP地址或ASN。</p>
                <h2>使用方法：</h2>
                <ol>
                    <li>在输入框中输入域名、IP地址或ASN。</li>
                    <li>点击搜索框下的按钮以获取结果。</li>
                    <li>提交查询后，您将看到域名、IP地址或ASN的详细WHOIS信息。</li>
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
    </main>
    <footer>
        <p>&copy; 2023-2025 <a href="https://github.com/iezx/Super-Whois" target="_blank">Super Whois</a> Version 1.1.2</p>
    </footer>
</body>
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

<script>
    // 查询历史记录本地存储与渲染
    const historyKey = 'superWhoisHistory';
    const historyList = document.getElementById('history-list');
    const queryInput = document.querySelector('input[name="query"]');

    function loadHistory() {
        let history = JSON.parse(localStorage.getItem(historyKey) || '[]');
        historyList.innerHTML = '';
        if (history.length === 0) {
            historyList.innerHTML = '<li style="color:#aaa;">暂无记录</li>';
            return;
        }
        history.slice(-10).reverse().forEach(item => {
            const li = document.createElement('li');
            li.className = 'history-item';
            li.textContent = item;
            li.title = '点击填充到查询框';
            li.onclick = () => {
                queryInput.value = item;
                queryInput.focus();
            };
            historyList.appendChild(li);
        });
    }

    function saveHistory(query) {
        let history = JSON.parse(localStorage.getItem(historyKey) || '[]');
        query = query.trim();
        if (!query) return;
        history = history.filter(item => item !== query);
        history.push(query);
        if (history.length > 20) history = history.slice(-20);
        localStorage.setItem(historyKey, JSON.stringify(history));
    }

    // 表单提交时保存历史
    const form = document.querySelector('form');
    form.addEventListener('submit', function(e) {
        saveHistory(queryInput.value);
    });

    // 页面加载时渲染历史
    window.addEventListener('DOMContentLoaded', loadHistory);
</script>
</body>
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
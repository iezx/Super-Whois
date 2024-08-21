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
        <img src="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png" alt="Icon" class="header-icon">
    </header>
    <main>
        <div class="form-container">
            <form method="post" action="">
                <div class="form-group">
                    <input type="text" name="query" placeholder="Enter the domain name, IP or ASN to search" required
                        value="<?php echo isset($_POST['query']) ? htmlspecialchars(removeSpaces($_POST['query']), ENT_QUOTES, 'UTF-8') : ''; ?>">
                </div>
                <button type="submit" name="submit" class="submit-button">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </button>
            </form>

            <?php
        // v1.1.1AX 优化CSS和代码

        // 去除输入域名中的所有空格
        function removeSpaces($input) {
            return preg_replace('/\s+/', '', $input);
        }
        
        function getDomainExtension($domain) {
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
                    // Protect server IP information
                    $result = array_map(function ($line) {
                        return str_replace('xx', 'Super Whois IP Privacy Function', $line);
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
                            'Record last updated on' => 'Last Updated Date',
                            'Last Updated' => 'Last Updated Date',
                            'modified' => 'Last Updated Date',
                            'Name Server' => 'DNS',
                            'Name Servers' => 'DNS',
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

                        foreach ($result as $line) {
                            foreach ($whoisDetails as $keyword => $infoType) {
                                if (preg_match('/^\s*' . preg_quote($keyword, '/') . '\s*(.*)$/i', $line, $matches)) {
                                    $value = trim($matches[1]);
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
                        stripos($line, 'Creation Date:') !== false||
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
            <div class="illustrate" id="englishGuide">

                <h4><a href="#" onclick="toggleLanguage('chinese')">中文说明</a></h4>
                <h3>Welcome to the Domain Name, IP&amp;ASN WHOIS Search System!</h3>
                <p>You can use this tool to query domain name information, IP addresses, and ASN information. Simply
                    enter the domain name, IP address, or ASN number in the input field above and select the appropriate
                    search type (Domain WHOIS Search or IP&amp;ASN WHOIS Search).</p>

                <h2>How to Use:</h2>
                <ol>
                    <li>Enter the domain name, IP address, or ASN number in the input field.</li>
                    <li>Select the appropriate search type (Domain or IP&amp;ASN WHOIS Search).</li>
                    <li>Click the "Enquiry" button to get the results.</li>
                    <li>After submitting your query, you will see detailed WHOIS information for the specified domain
                        name, IP address, or ASN number.</li>
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
    </main>
    <footer>
        <p>&copy; 2024 <a href="https://github.com/iezx/Super-Whois" target="_blank">Super Whois</a> Version 1.1.1AX
        </p>
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
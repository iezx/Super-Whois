<?php
// index.php
// v2.0.0 

// Automatic redirect logic
if (empty($_SERVER['QUERY_STRING'])) {
    $default_lang = isset($_COOKIE['lang']) ? $_COOKIE['lang'] : 'en';
    header('Location: index.php?lang=' . $default_lang);
    exit();
}

// Check for PHP intl extension
if (!function_exists('idn_to_ascii')) {
    die("Error: The 'intl' PHP extension is missing. Please enable 'extension=intl' in your php.ini to support IDN lookups.");
}

require_once 'languages.php';

// ---Language---
$supported_langs = ['en', 'zh'];
$lang = 'en';

if (isset($_GET['lang'])) {
    $get_lang = strtolower($_GET['lang']);
    if (in_array($get_lang, $supported_langs)) {
        $lang = $get_lang;
        setcookie('lang', $lang, time() + (86400 * 30), "/");
    }
} elseif (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $supported_langs)) {
    $lang = $_COOKIE['lang'];
}
$T = get_language_strings($lang);

// --- Core Functions ---
function sanitizeQuery($input) {
    $query = preg_replace('/^https?:\/\//i', '', trim($input));
    $parts = explode('/', $query, 2);
    $query = $parts[0];
    $query = preg_replace('/\s+/', '', $query);
    return $query;
}

function getDomainExtension($domain) {
    $domainAscii = idn_to_ascii($domain, IDNA_DEFAULT);
    if ($domainAscii === false) return '';
    $parts = explode('.', $domainAscii);
    return strtolower(end($parts));
}

function queryWhoisServer($server, $query) {
    $whois = @fsockopen($server, 43, $errno, $errstr, 10);
    if (!$whois) { return []; }
    fwrite($whois, $query . "\r\n");
    $response = '';
    while (!feof($whois)) { $response .= fgets($whois, 128); }
    fclose($whois);
    return explode("\n", $response);
}


// Censors IPv4 and IPv6 addresses in an array of strings.
function censorIPsInArray(array $lines): array {
    $censoredLines = [];
    $ipPattern = '/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:.]+\b)/i';
    $replacement = '[IP REDACTED]';
    foreach ($lines as $line) {
        $censoredLines[] = preg_replace($ipPattern, $replacement, $line);
    }
    return $censoredLines;
}


// --- Get query content ---
$current_query = '';
if (!empty($_POST['query'])) {
    $current_query = sanitizeQuery($_POST['query']);
} elseif (!empty($_GET['query'])) {
    $current_query = sanitizeQuery($_GET['query']);
}


// --- Main Logic Functions ---
function performWhoisQuery($domain, $T) {
    require __DIR__ . '/whois_servers.php';
    global $lang;
    $domainAscii = idn_to_ascii($domain, IDNA_DEFAULT);
    if ($domainAscii === false) { echo '<div class="result-card"><h3>' . $T['invalid_query'] . '</h3></div>'; return; }
    
    $tld = getDomainExtension($domain);
    if (empty($tld) || !isset($whoisServers[$tld])) { echo '<div class="result-card"><h3>' . $T['unsupported_tld'] . '</h3></div>'; return; }
    
    $server = $whoisServers[$tld];
    $queryToSend = $domainAscii;
    if ($tld === 'de') {
        $queryToSend = "-T dn,ace " . $domainAscii;
    }

    $rawResult = queryWhoisServer($server, $queryToSend);
    
    if (empty($rawResult)) { echo '<div class="result-card"><h3>' . $T['no_info_found'] . '</h3></div>'; return; }

    // Use original data for keyword check, but censored data for display
    $rawResultString = strtolower(implode("\n", $rawResult));
    $censoredResult = censorIPsInArray($rawResult);

    $raw_data_html = '<div class="raw-data-container"><button class="details-toggle" onclick="toggleDetails(this)">' . $T['show_raw_data'] . '</button><div class="details-content"><pre>' . htmlspecialchars(implode("\n", $censoredResult)) . '</pre></div></div>';
    
    $shareable_url = 'index.php?lang=' . $lang . '&query=' . urlencode($domain);
    $copy_button_html = '<button class="copy-link-btn" onclick="copyToClipboard(\'' . $shareable_url . '\', this)"><i class="fa-solid fa-link"></i> ' . $T['copy_link_button'] . '</button>';

    $unregistered_keywords = ['not found', 'no match for', 'no data found', 'no entries found', 'is available for registration', 'domain not found', 'is not registered', 'not exist'];
    foreach ($unregistered_keywords as $keyword) {
        if (strpos($rawResultString, $keyword) !== false) {
            echo '<div class="result-card status-available">';
            echo '<div class="result-header"><h2>' . htmlspecialchars($domain) . '</h2>' . $copy_button_html . '</div>';
            echo '<p class="status-text">' . $T['domain_available'] . '</p>';
            echo $raw_data_html;
            echo '</div>';
            return;
        }
    }

    $reserved_keywords = ['reserved', 'client hold', 'serverhold', 'inactive', 'registry lock'];
    foreach ($reserved_keywords as $keyword) {
        if (strpos($rawResultString, $keyword) !== false) {
            echo '<div class="result-card status-reserved">';
            echo '<div class="result-header"><h2>' . htmlspecialchars($domain) . '</h2>' . $copy_button_html . '</div>';
            echo '<p class="status-text">' . $T['domain_reserved'] . '</p>';
            echo $raw_data_html;
            echo '</div>';
            return;
        }
    }
    
    // Pass the censored data to the parsing and display functions
    $parsedInfo = parseWhoisData($censoredResult, $T);
    displayWhoisInfo($domain, $server, $parsedInfo, $censoredResult, $T);
}
function performIPWhoisQuery($ip, $T) {
    $server = 'whois.apnic.net';
    $result = queryWhoisServer($server, $ip);
    $censoredResult = censorIPsInArray($result); // Censor IPs

    echo '<div class="result-card">';
    if (!empty($censoredResult) && count($censoredResult) > 5) {
        echo '<h2>' . htmlspecialchars($ip) . ' ' . $T['whois_information'] . '</h2>';
        echo '<p class="searched-from">' . $T['searched_from'] . ': ' . htmlspecialchars($server) . '</p>';
        echo '<div class="raw-data-wrapper"><pre>' . htmlspecialchars(implode("\n", $censoredResult)) . '</pre></div>';
    } else { echo '<h3>' . $T['no_info_found'] . '</h3>'; }
    echo '</div>';
}
function performASNWhoisQuery($asn, $T) {
    $server = 'whois.arin.net';
    $result = queryWhoisServer($server, $asn);
    $censoredResult = censorIPsInArray($result); // Censor IPs

    echo '<div class="result-card">';
    if (!empty($censoredResult) && count($censoredResult) > 5) {
        echo '<h2>' . htmlspecialchars($asn) . ' ' . $T['whois_information'] . '</h2>';
        echo '<p class="searched-from">' . $T['searched_from'] . ': ' . htmlspecialchars($server) . '</p>';
        echo '<div class="raw-data-wrapper"><pre>' . htmlspecialchars(implode("\n", $censoredResult)) . '</pre></div>';
    } else { echo '<h3>' . $T['no_info_found'] . '</h3>'; }
    echo '</div>';
}
function parseWhoisData($rawResult, $T) {
    $info = [
        $T['group_dates'] => [], $T['group_registrar_contact'] => [],
        $T['group_nameservers'] => [], $T['group_status'] => [], $T['group_dnssec'] => [],
    ];
    $patterns = [
        '/^(Registry Expiry Date|Expiration Date|expires|Expiry Date):/i' => [$T['group_dates'], 'Expiration Date'],
        '/^(Creation Date|created|Registration Date):/i' => [$T['group_dates'], 'Creation Date'],
        '/^(Updated Date|Last-Modified|last-update):/i' => [$T['group_dates'], 'Updated Date'],
        '/^(Registrar WHOIS Server|Registrar:|Sponsoring Registrar):/i' => [$T['group_registrar_contact'], 'Registrar'],
        '/^Registrar IANA ID:/i' => [$T['group_registrar_contact'], 'Registrar IANA ID'],
        '/^Registrar Abuse Contact Email:/i' => [$T['group_registrar_contact'], 'Registrar Abuse Email'],
        '/^Registrant Name:/i' => [$T['group_registrar_contact'], 'Registrant Name'],
        '/^Registrant Organization:/i' => [$T['group_registrar_contact'], 'Registrant Organization'],
        '/^Name Server:|nserver:/i' => [$T['group_nameservers'], null],
        '/^Domain Status:|Status:/i' => [$T['group_status'], null],
        '/^DNSSEC:/i' => [$T['group_dnssec'], null]
    ];
    foreach ($rawResult as $line) {
        $line = trim($line);
        if (empty($line) || strpos($line, '>>>') === 0) continue;
        foreach ($patterns as $pattern => $map) {
            if (preg_match($pattern, $line, $matches)) {
                list($group, $key) = $map;
                $value = trim(ltrim(preg_replace($pattern, '', $line, 1), ': '));
                if ($key === null) {
                    if (!in_array($value, $info[$group])) $info[$group][] = $value;
                } else {
                    if (!isset($info[$group][$key])) $info[$group][$key] = $value;
                }
                continue 2;
            }
        }
    }
    return $info;
}
function displayWhoisInfo($domain, $server, $parsedInfo, $rawResult, $T) {
    global $lang; 
    $shareable_url = 'index.php?lang=' . $lang . '&query=' . urlencode($domain);

    echo '<div class="result-card">';
    echo '<div class="result-header">';
    echo '  <h2><i class="fa-solid fa-circle-check" style="color: #28a745;"></i> ' . htmlspecialchars($domain) . ' ' . $T['domain_registered'] . '</h2>';
    echo '  <button class="copy-link-btn" onclick="copyToClipboard(\'' . $shareable_url . '\', this)"><i class="fa-solid fa-link"></i> ' . $T['copy_link_button'] . '</button>';
    echo '</div>';
    echo '<p class="searched-from">' . $T['searched_from'] . ': ' . htmlspecialchars($server) . '</p>';
    foreach ($parsedInfo as $groupName => $details) {
        if ($groupName === $T['group_dnssec']) {
            $dnssec_status = "Unknown";
            if (!empty($details)) {
                $dnssec_val = strtolower(implode(" ", $details));
                $dnssec_status = (strpos($dnssec_val, 'unsigned') === false) ? 'Yes' : 'No';
            }
            if ($dnssec_status !== "Unknown") {
                echo '<div class="info-group"><h3>' . htmlspecialchars($groupName) . '</h3><p>' . htmlspecialchars($dnssec_status) . '</p></div>';
            }
            continue;
        }
        if (empty($details)) continue;
        echo '<div class="info-group"><h3>' . htmlspecialchars($groupName) . '</h3>';
        if (is_array($details)) {
            echo '<ul>';
            if (isset($details[0])) {
                foreach ($details as $item) echo '<li>' . htmlspecialchars($item) . '</li>';
            } else {
                foreach ($details as $key => $value) echo '<li><strong>' . htmlspecialchars($key) . ':</strong> ' . htmlspecialchars($value) . '</li>';
            }
            echo '</ul>';
        }
        echo '</div>';
    }
    echo '<div class="raw-data-container"><button class="details-toggle" onclick="toggleDetails(this)">' . $T['show_raw_data'] . '</button><div class="details-content"><pre>' . htmlspecialchars(implode("\n", $rawResult)) . '</pre></div></div>';
    echo '</div>';
}
?>
<!DOCTYPE html>
<html lang="<?php echo $lang; ?>">
<head>
    <meta charset="UTF-8">
    <title><?php echo $T['page_title']; ?></title>
    <link rel="stylesheet" type="text/css" href="./style.css?v=1.6">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="description" content="<?php echo $T['meta_description']; ?>">
    <link rel="shortcut icon" href="https://cdn.807070.xyz/img/new/2023/01/14/63c2a68d3bb10.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <header>
        <div class="header-content">
            <h2><?php echo $T['header_title']; ?></h2>
            <div class="language-switcher">
                <?php
                $en_link = '?lang=en';
                $zh_link = '?lang=zh';
                if (!empty($current_query)) {
                    $en_link .= '&query=' . urlencode($current_query);
                    $zh_link .= '&query=' . urlencode($current_query);
                }
                ?>
                <a href="<?php echo $en_link; ?>" <?php if($lang == 'en') echo 'class="active"'; ?>>English</a>
                <a href="<?php echo $zh_link; ?>" <?php if($lang == 'zh') echo 'class="active"'; ?>>中文</a>
            </div>
        </div>
    </header>
    <main>
        <div class="search-card">
            <form method="post" action="?lang=<?php echo $lang; ?>">
                <div class="input-wrapper">
                     <i class="fa-solid fa-magnifying-glass"></i>
                    <input type="text" name="query" placeholder="<?php echo $T['placeholder']; ?>" required value="<?php echo htmlspecialchars($current_query, ENT_QUOTES, 'UTF-8'); ?>">
                </div>
                <button type="submit" name="submit" class="submit-button"><?php echo $T['search_button']; ?></button>
            </form>
        </div>
        <?php
        if (!empty($current_query)) {
            $ascii_query = idn_to_ascii($current_query, IDNA_DEFAULT);
            if ($ascii_query === false && !filter_var($current_query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && !preg_match('/^AS\d+$/i', $current_query)) {
                echo '<div class="result-card"><h3>' . $T['invalid_query'] . '</h3></div>';
            } elseif (filter_var($current_query, FILTER_VALIDATE_IP)) {
                performIPWhoisQuery($current_query, $T);
            } elseif (preg_match('/^AS\d+$/i', $current_query)) {
                performASNWhoisQuery($current_query, $T);
            } elseif (filter_var($ascii_query, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                performWhoisQuery($current_query, $T);
            } else {
                echo '<div class="result-card"><h3>' . $T['invalid_query'] . '</h3></div>';
            }
        }
        ?>
        <div class="actions-container">
            <button id="toggle-guides-btn" class="secondary-button"></button>
        </div>
        
        <div id="guides-container">
            <div class="illustrate-card" id="englishGuide">
                <div class="card-header">
                    <h3>Guide</h3>
                </div>
                <ol>
                    <li>Enter a Domain (e.g., `google.com`), IP (e.g., `8.8.8.8`), or ASN (e.g., `AS15169`).</li>
                    <li>Click the "Search" button to get detailed WHOIS information.</li>
                </ol>
            </div>
            <div class="illustrate-card" id="chineseGuide">
                 <div class="card-header">
                    <h3>使用指南</h3>
                 </div>
                <ol>
                    <li>输入域名（如 `google.com`）、IP（如 `8.8.8.8`）或ASN（如 `AS15169`）。</li>
                    <li>点击“查询”按钮以获取详细的WHOIS信息。</li>
                </ol>
            </div>
        </div>

        <div class="history-card">
            <div class="history-header">
                <h3><?php echo $T['history_records_title']; ?></h3>
                <button class="clear-button" onclick="clearHistory()"><?php echo $T['clear_history_button']; ?></button>
            </div>
            <p class="history-info"><?php echo $T['history_info']; ?></p>
            <ul id="history-list"></ul>
        </div>
    </main>
    <footer>
        <p><?php echo $T['footer_text']; ?> | <a href="https://github.com/iezx/Super-Whois" target="_blank">GitHub</a></p>
    </footer>

    <script>
    document.addEventListener('DOMContentLoaded', () => {
        const App = {
            guidesContainer: document.getElementById('guides-container'),
            toggleBtn: document.getElementById('toggle-guides-btn'),
            englishGuide: document.getElementById('englishGuide'),
            chineseGuide: document.getElementById('chineseGuide'),
            historyList: document.getElementById('history-list'),
            queryInput: document.querySelector('input[name="query"]'),
            form: document.querySelector('form'),
            lang: '<?php echo $lang; ?>',
            guidesVisible: true,
            text: {
                showGuides: '<?php echo $T['toggle_guides_button']; ?>',
                hideGuides: '<?php echo $T['hide_guides_button']; ?>',
                showRaw: '<?php echo $T['show_raw_data']; ?>',
                hideRaw: '<?php echo $T['hide_raw_data']; ?>',
                noHistory: '<?php echo $T['no_history']; ?>',
                copied: '<?php echo $T['copied_feedback']; ?>',
                copyFailed: '<?php echo $T['copy_failed']; ?>',
            },
            historyKey: 'superWhoisHistory_v2',

            init() {
                this.bindEvents();
                this.updateUIVisibility();
                this.loadHistory();
            },

            bindEvents() {
                this.toggleBtn.addEventListener('click', () => {
                    this.guidesVisible = !this.guidesVisible;
                    this.updateUIVisibility();
                });

                this.form.addEventListener('submit', () => {
                    if (this.queryInput.value) this.saveHistory(this.queryInput.value);
                });
            },

            updateUIVisibility() {
                this.guidesContainer.classList.toggle('is-hidden', !this.guidesVisible);
                this.toggleBtn.textContent = this.guidesVisible ? this.text.hideGuides : this.text.showGuides;
                this.englishGuide.classList.toggle('is-hidden', this.lang !== 'en');
                this.chineseGuide.classList.toggle('is-hidden', this.lang !== 'zh');
            },

            loadHistory() {
                const history = JSON.parse(localStorage.getItem(this.historyKey) || '[]');
                this.historyList.innerHTML = '';
                if (history.length === 0) {
                    this.historyList.innerHTML = `<li class="no-history">${this.text.noHistory}</li>`;
                    return;
                }
                history.slice(-10).reverse().forEach(item => {
                    const li = document.createElement('li');
                    li.className = 'history-item';
                    li.textContent = item;
                    li.title = 'Click to fill';
                    li.onclick = () => { this.queryInput.value = item; this.queryInput.focus(); };
                    this.historyList.appendChild(li);
                });
            },

            saveHistory(query) {
                let history = JSON.parse(localStorage.getItem(this.historyKey) || '[]');
                query = query.trim().toLowerCase();
                if (!query) return;
                history = history.filter(item => item !== query);
                history.push(query);
                if (history.length > 20) history.splice(0, history.length - 20);
                localStorage.setItem(this.historyKey, JSON.stringify(history));
            },
        };

        window.copyToClipboard = function(text, button) {
            const fullUrl = new URL(text, window.location.href).href;
            
            navigator.clipboard.writeText(fullUrl).then(() => {
                const originalText = button.innerHTML;
                button.innerHTML = App.text.copied; 
                button.disabled = true;
                setTimeout(() => {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }, 2000);
            }).catch(err => {
                console.error('Copy failed: ', err);
                alert(App.text.copyFailed);
            });
        }

        window.toggleDetails = function(button) {
            const content = button.nextElementSibling;
            const isVisible = content.style.display === 'block';
            content.style.display = isVisible ? 'none' : 'block';
            button.textContent = isVisible ? App.text.showRaw : App.text.hideRaw;
        }

        window.clearHistory = function() {
            localStorage.removeItem(App.historyKey);
            App.loadHistory();
        }

        App.init();
    });
</script>
</body>
</html>
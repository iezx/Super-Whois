<?php
// languages.php

function get_language_strings(string $lang = 'en'): array {

    // ── English (base / fallback) ────────────────────────────────────────────
    $strings['en'] = [
        // Page meta
        'page_title'        => 'Super Whois - Modern WHOIS Lookup',
        'meta_description'  => 'Fast and modern WHOIS lookup for domains, IPs, and ASNs. Clean, readable, structured results.',
        'header_title'      => 'Super Whois',

        // Search form
        'placeholder'       => 'e.g. google.com,  8.8.8.8,  or  AS15169',
        'search_button'     => 'Search',

        // Result card
        'whois_information'  => 'WHOIS Information',
        'searched_from'      => 'Queried from',
        'domain_registered'  => 'is already registered.',
        'domain_available'   => 'Congratulations! This domain is available for registration.',
        'domain_reserved'    => 'This domain is reserved by the registry or is invalid.',
        'show_raw_data'      => 'Show Raw Data',
        'hide_raw_data'      => 'Hide Raw Data',
        'copy_link_button'   => 'Copy Link',
        'copied_feedback'    => 'Copied!',
        'copy_failed'        => 'Failed to copy!',

        // Subdomain suggestion
        'subdomain_hint'        => 'Did you mean to look up',
        'subdomain_hint_suffix' => '?',
        'subdomain_search_btn'  => 'Search',

        // Parsed field group headings
        'group_dates'             => 'Important Dates',
        'group_registrar_contact' => 'Registrar & Contact',
        'group_nameservers'       => 'Nameservers',
        'group_status'            => 'Domain Status',
        'group_dnssec'            => 'DNSSEC',

        // Error messages
        'invalid_query'     => 'Invalid query. Please enter a valid Domain, IP, or ASN.',
        'unsupported_tld'   => 'WHOIS lookup for this TLD is not supported.',
        'no_info_found'     => 'Could not retrieve WHOIS information.',

        // Guide toggle
        'toggle_guides_button' => 'Show Guide',
        'hide_guides_button'   => 'Hide Guide',

        // Guide body — step3 (thin/thick technical detail) intentionally removed
        'guide_title'  => 'User Guide',
        'guide_step1'  => 'Enter a <strong>Domain</strong> (e.g. <code>google.com</code>), <strong>IP</strong> (e.g. <code>8.8.8.8</code>), or <strong>ASN</strong> (e.g. <code>AS15169</code>).',
        'guide_step2'  => 'Click <strong>Search</strong> — the system queries the authoritative WHOIS server directly.',
        'guide_step3'  => 'Click <strong>Show Raw Data</strong> to inspect the full unprocessed WHOIS response.',
        'guide_step4'  => 'Click <strong>Copy Link</strong> to share a direct URL to this lookup.',
        'guide_step5'  => 'The <strong>API</strong> button (top-right) opens the programmatic access documentation.',
        'guide_step6'  => 'Use the <i class="fa-solid fa-moon"></i> button to switch between light and dark mode.',

        // History
        'history_records_title' => 'Recent Lookups',
        'history_info'          => 'Your last 10 queries are shown here. Stored locally in your browser.',
        'clear_history_button'  => 'Clear',
        'no_history'            => 'No history yet.',
        'history_click_hint'    => 'Click to search',

        // Footer
        'footer_text'      => '&copy; ' . date('Y') . ' Super Whois',
        'footer_api_link'  => 'API Docs',
        'footer_github'    => 'GitHub',

        // ── API docs page ──────────────────────────────────────────────────
        'api_page_title'           => 'Super Whois — API Documentation',
        'api_hero_title'           => 'Super Whois API',
        'api_hero_subtitle'        => 'Simple, JSON-based WHOIS lookups for domains, IPs, and ASNs.',
        'api_back_link'            => 'Back to lookup',
        'api_section_base_url'     => 'Base URL',
        'api_section_auth'         => 'Authentication',
        'api_auth_public'          => 'The API is publicly accessible without a key. Authenticated requests bypass the rate limit.',
        'api_auth_protected'       => 'The API is key-protected — all requests require a valid API key. Authenticated requests bypass the rate limit.',
        'api_auth_keys_note'       => 'To issue API keys, create <code>api_keys.php</code> in the same directory:',
        'api_section_rate'         => 'Rate Limiting',
        'api_rate_note'            => 'Unauthenticated requests are limited to <strong>%d requests per hour</strong> per IP address.',
        'api_rate_header_name'     => 'Response Header',
        'api_rate_header_desc'     => 'Description',
        'api_rate_limit_label'     => 'Maximum requests per window',
        'api_rate_remaining_label' => 'Requests remaining this window',
        'api_rate_reset_label'     => 'Unix timestamp when window resets',
        'api_section_params'       => 'Query Parameters',
        'api_param_name'           => 'Parameter',
        'api_param_required'       => 'Required',
        'api_param_desc'           => 'Description',
        'api_param_q_desc'         => 'The target to look up. Accepts a domain name (e.g. <code>google.com</code>), IPv4 / IPv6 address, or ASN (e.g. <code>AS15169</code>).',
        'api_param_key_desc'       => 'API key. Bypasses rate limiting when valid.',
        'api_section_endpoints'    => 'Endpoints & Examples',
        'api_endpoint_domain'      => 'Domain lookup',
        'api_endpoint_ip'          => 'IP lookup',
        'api_endpoint_asn'         => 'ASN lookup',
        'api_section_response'     => 'Response Fields',
        'api_section_sample'       => 'Sample Response',
        'api_section_errors'       => 'Error Codes',
        'api_error_meaning'        => 'Meaning',
        'api_error_400'            => 'Bad Request — invalid or missing <code>q</code> parameter',
        'api_error_401'            => 'Unauthorized — API key required but not provided or invalid',
        'api_error_429'            => 'Too Many Requests — rate limit exceeded',
        'api_error_500'            => 'Server Error — PHP extension missing or misconfiguration',
        'api_section_try'          => 'Try It',
        'api_try_send'             => 'Send',
        'api_try_loading'          => 'Loading…',
        'api_try_network_error'    => 'Network error',
        'api_section_examples'     => 'Code Examples',
        'api_example_js'           => 'JavaScript (fetch)',
        'api_example_python'       => 'Python (requests)',
        'api_example_curl'         => 'cURL',
        // response field table
        'api_field_query'          => 'The sanitized input query',
        'api_field_query_type'     => 'domain | ipv4 | ipv6 | asn',
        'api_field_status'         => 'registered | available | found | unsupported_tld | error',
        'api_field_whois_server'   => 'The WHOIS server that provided the data',
        'api_field_timestamp'      => 'UTC time of this API response',
        'api_field_data'           => 'Structured parsed fields (domain queries only, when registered)',
        'api_field_creation'       => 'Domain registration date',
        'api_field_expiration'     => 'Domain expiry date',
        'api_field_updated'        => 'Last updated date',
        'api_field_registrar'      => 'Registrar name',
        'api_field_nameservers'    => 'List of nameservers (lowercase, sorted)',
        'api_field_statuses'       => 'Domain EPP status codes',
        'api_field_dnssec'         => 'signed or unsigned',
        'api_field_raw'            => 'Full raw WHOIS response (IPs redacted)',
    ];

    // ── Chinese overrides ────────────────────────────────────────────────────
    $strings['zh'] = [
        // Page meta
        'page_title'       => 'Super Whois - WHOIS 查询工具',
        'meta_description' => '快速、现代化的域名、IP 及 ASN WHOIS 查询工具，提供清晰、易读的结构化结果。',

        // Search
        'placeholder'  => '例如: google.com、8.8.8.8 或 AS15169',
        'search_button' => '查询',

        // Result
        'whois_information' => 'WHOIS 信息',
        'searched_from'     => '查询自',
        'domain_registered' => '已被注册。',
        'domain_available'  => '恭喜！该域名可以注册。',
        'domain_reserved'   => '该域名为注册局保留域名或无效。',
        'show_raw_data'     => '显示原始数据',
        'hide_raw_data'     => '隐藏原始数据',
        'copy_link_button'  => '复制链接',
        'copied_feedback'   => '已复制！',
        'copy_failed'       => '复制失败！',

        // Subdomain suggestion
        'subdomain_hint'        => '您是否想查询',
        'subdomain_hint_suffix' => '？',
        'subdomain_search_btn'  => '查询',

        // Group headings
        'group_dates'             => '重要日期',
        'group_registrar_contact' => '注册商与联系人',
        'group_nameservers'       => '域名服务器',
        'group_status'            => '域名状态',
        'group_dnssec'            => 'DNSSEC',

        // Errors
        'invalid_query'    => '无效查询。请输入有效的域名、IP 或 ASN。',
        'unsupported_tld'  => '暂不支持该域名后缀的 WHOIS 查询。',
        'no_info_found'    => '无法获取 WHOIS 信息。',

        // Guide toggle
        'toggle_guides_button' => '显示指南',
        'hide_guides_button'   => '隐藏指南',

        // Guide body
        'guide_title'  => '使用指南',
        'guide_step1'  => '在搜索框输入<strong>域名</strong>（如 <code>google.com</code>）、<strong>IP</strong>（如 <code>8.8.8.8</code>）或 <strong>ASN</strong>（如 <code>AS15169</code>）。',
        'guide_step2'  => '点击<strong>查询</strong>，系统将直接向权威 WHOIS 服务器发起请求。',
        'guide_step3'  => '点击<strong>显示原始数据</strong>可查看完整的原始 WHOIS 响应。',
        'guide_step4'  => '点击<strong>复制链接</strong>可分享本次查询的直达链接。',
        'guide_step5'  => '右上角 <strong>API</strong> 按钮可查看程序化调用文档。',
        'guide_step6'  => '点击 <i class="fa-solid fa-moon"></i> 图标可切换深色 / 浅色模式。',

        // History
        'history_records_title' => '查询历史',
        'history_info'          => '此处显示最近 10 条查询记录，保存在您的本地浏览器中。',
        'clear_history_button'  => '清空',
        'no_history'            => '暂无历史记录。',
        'history_click_hint'    => '点击以查询',

        // Footer
        'footer_api_link' => 'API 文档',
        'footer_github'   => 'GitHub',

        // API docs page
        'api_page_title'           => 'Super Whois — API 文档',
        'api_hero_title'           => 'Super Whois API',
        'api_hero_subtitle'        => '简单易用的 JSON 格式 WHOIS 查询接口，支持域名、IP 及 ASN。',
        'api_back_link'            => '返回查询页',
        'api_section_base_url'     => '基础 URL',
        'api_section_auth'         => '认证',
        'api_auth_public'          => '该 API 无需密钥即可公开访问。使用 API Key 的请求可绕过速率限制。',
        'api_auth_protected'       => '该 API 需要有效的 API Key 才能访问。使用 API Key 的请求可绕过速率限制。',
        'api_auth_keys_note'       => '如需创建 API Key，请在相同目录下新建 <code>api_keys.php</code> 文件：',
        'api_section_rate'         => '速率限制',
        'api_rate_note'            => '未认证请求每小时每个 IP 最多 <strong>%d 次</strong>。',
        'api_rate_header_name'     => '响应头',
        'api_rate_header_desc'     => '说明',
        'api_rate_limit_label'     => '每个时间窗口的最大请求数',
        'api_rate_remaining_label' => '当前窗口剩余请求数',
        'api_rate_reset_label'     => '时间窗口重置的 Unix 时间戳',
        'api_section_params'       => '请求参数',
        'api_param_name'           => '参数',
        'api_param_required'       => '必填',
        'api_param_desc'           => '说明',
        'api_param_q_desc'         => '查询目标。支持域名（如 <code>google.com</code>）、IPv4/IPv6 地址，或 ASN（如 <code>AS15169</code>）。',
        'api_param_key_desc'       => 'API Key，有效时可绕过速率限制。',
        'api_section_endpoints'    => '接口与示例',
        'api_endpoint_domain'      => '域名查询',
        'api_endpoint_ip'          => 'IP 查询',
        'api_endpoint_asn'         => 'ASN 查询',
        'api_section_response'     => '响应字段说明',
        'api_section_sample'       => '响应示例',
        'api_section_errors'       => '错误码',
        'api_error_meaning'        => '含义',
        'api_error_400'            => '请求错误 — <code>q</code> 参数无效或缺失',
        'api_error_401'            => '未授权 — 需要 API Key 但未提供或无效',
        'api_error_429'            => '请求过频 — 超出速率限制',
        'api_error_500'            => '服务器错误 — PHP 扩展缺失或配置错误',
        'api_section_try'          => '在线测试',
        'api_try_send'             => '发送',
        'api_try_loading'          => '加载中…',
        'api_try_network_error'    => '网络错误',
        'api_section_examples'     => '代码示例',
        'api_example_js'           => 'JavaScript (fetch)',
        'api_example_python'       => 'Python (requests)',
        'api_example_curl'         => 'cURL',
        // response field table
        'api_field_query'          => '经过处理的查询输入',
        'api_field_query_type'     => 'domain | ipv4 | ipv6 | asn',
        'api_field_status'         => 'registered | available | found | unsupported_tld | error',
        'api_field_whois_server'   => '实际提供数据的 WHOIS 服务器',
        'api_field_timestamp'      => '本次 API 响应的 UTC 时间',
        'api_field_data'           => '结构化解析字段（仅域名查询且已注册时返回）',
        'api_field_creation'       => '域名注册日期',
        'api_field_expiration'     => '域名到期日期',
        'api_field_updated'        => '最后更新日期',
        'api_field_registrar'      => '注册商名称',
        'api_field_nameservers'    => '域名服务器列表（小写，已排序）',
        'api_field_statuses'       => '域名 EPP 状态码',
        'api_field_dnssec'         => 'signed（已签名）或 unsigned（未签名）',
        'api_field_raw'            => '完整原始 WHOIS 响应（IP 已脱敏）',
    ];

    if ($lang !== 'en' && isset($strings[$lang])) {
        return array_merge($strings['en'], $strings[$lang]);
    }

    return $strings['en'];
}

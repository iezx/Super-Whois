<?php
// languages.php

function get_language_strings($lang = 'en') {
    $strings['en'] = [
        'page_title' => "Super Whois - Modern WHOIS Lookup",
        'meta_description' => "Fast and modern WHOIS lookup tool for domains, IPs, and ASNs. Clean, readable, and structured results.",
        'header_title' => "Super Whois",
        'placeholder' => "e.g., google.com, 8.8.8.8, or AS15169",
        'search_button' => "Search",
        'history_records_title' => "Recent Lookups",
        'history_info' => "Your last 10 queries are shown here. Stored locally.",
        'clear_history_button' => "Clear",
        'no_history' => "No history yet.",
        'invalid_query' => "Invalid Query. Please enter a valid Domain, IP, or ASN.",
        'unsupported_tld' => "WHOIS lookup for this TLD is not supported.",
        'no_info_found' => "Could not retrieve WHOIS information.",
        'whois_information' => "WHOIS Information",
        'searched_from' => "Queried from",
        'show_raw_data' => "Show Raw Data",
        'hide_raw_data' => "Hide Raw Data",
        'toggle_guides_button' => "Show Guide",
        'hide_guides_button' => "Hide Guide",
        'footer_text' => "&copy; " . date('Y') . " Super Whois",
        'group_dates' => "Important Dates",
        'group_registrar_contact' => "Registrar & Contact",
        'group_nameservers' => "Nameservers",
        'group_status' => "Domain Status",
        'group_dnssec' => "DNSSEC",
        'domain_available' => 'Congratulations! This domain is available for registration.',
        'domain_reserved' => 'This domain is reserved by the registry or is invalid.',
        'domain_registered' => 'is already registered.',
        'copy_link_button' => 'Copy Result Link',
        'copied_feedback' => 'Copied!',
        'copy_failed' => 'Failed to copy link!', 
    ];

    $strings['zh'] = [
        'page_title' => "Super Whois - WHOIS查询工具",
        'meta_description' => "一个快速、现代化的域名、IP及ASN的WHOIS查询工具。提供清晰、易读、结构化的查询结果。",
        'header_title' => "Super Whois",
        'placeholder' => "例如: google.com, 8.8.8.8, 或 AS15169",
        'search_button' => "查询",
        'history_records_title' => "查询历史",
        'history_info' => "此处显示最近10条查询。记录保存在您的本地浏览器中。",
        'clear_history_button' => "清空",
        'no_history' => "暂无历史记录。",
        'invalid_query' => "无效查询。请输入一个有效的域名、IP或ASN。",
        'unsupported_tld' => "不支持此域名后缀的WHOIS查询。",
        'no_info_found' => "无法获取WHOIS信息。",
        'whois_information' => "WHOIS信息",
        'searched_from' => "查询自",
        'show_raw_data' => "显示原始数据",
        'hide_raw_data' => "隐藏原始数据",
        'toggle_guides_button' => "显示指南",
        'hide_guides_button' => "隐藏指南",
        'footer_text' => "&copy; " . date('Y') . " Super Whois",
        'group_dates' => "重要日期",
        'group_registrar_contact' => "注册商与联系人",
        'group_nameservers' => "域名服务器",
        'group_status' => "域名状态",
        'group_dnssec' => "DNSSEC",
        'domain_available' => '恭喜！该域名可以注册。',
        'domain_reserved' => '该域名为注册局保留域名或无效。',
        'domain_registered' => '已被注册。',
        'copy_link_button' => '复製结果链接',
        'copied_feedback' => '已复製!',
        'copy_failed' => '复製链接失败！', 
    ];

    if ($lang !== 'en' && isset($strings[$lang])) {
        return array_merge($strings['en'], $strings[$lang]);
    }

    return $strings['en'];
}
?>
<?php
/*
 * mwddns/locale/zh_CN.php – Simplified Chinese (简体中文) translations
 *
 * Placed at: /usr/local/pkg/mwddns/locale/zh_CN.php
 *
 * Used by mwddns_t() in mwddns.inc when pfSense system language is zh_CN.
 * Keys are the original English strings; values are the translations.
 * Strings not listed here fall back to the original English.
 */

return [

    /* ── Shared labels ──────────────────────────────────────────────────── */
    'Services'                   => '服务',
    'Multi-WAN DDNS'             => '多广域网 DDNS',
    'Name'                       => '名称',
    'Provider'                   => '服务提供商',
    'Hostname'                   => '主机名',
    'Interfaces'                 => '接口',
    'Add'                        => '添加',
    'Edit'                       => '编辑',
    'Delete'                     => '删除',
    'Save'                       => '保存',
    'Cancel'                     => '取消',
    'Status'                     => '状态',
    'Actions'                    => '操作',
    'Error'                      => '错误',
    'Never'                      => '从未',
    'Configuration'              => '配置',

    /* ── mwddns.php – list page ─────────────────────────────────────────── */
    'Rule saved successfully.'                                              => '规则已成功保存。',
    'Rule deleted.'                                                         => '规则已删除。',
    'DNS records updated successfully.'                                     => 'DNS 记录已成功更新。',
    'DNS update completed with errors. Check individual rule status.'       => 'DNS 更新完成，但存在错误。请检查各规则状态。',
    'Multi-WAN DDNS Rules'                                                  => '多广域网 DDNS 规则',
    'Interfaces / Current IPs'                                              => '接口 / 当前 IP',
    'Last Updated'                                                          => '最后更新',
    'No rules configured. Click'                                            => '未配置规则。点击',
    'to create one.'                                                        => '以创建规则。',
    'DNS record matches this IP'                                            => 'DNS 记录与此 IP 匹配',
    'DNS record does NOT contain this IP'                                   => 'DNS 记录不包含此 IP',
    'No IPv4'                                                               => '无 IPv4',
    'No IPv6'                                                               => '无 IPv6',
    'Delete this rule?'                                                     => '确认删除此规则？',

    /* ── mwddns_edit.php – edit / add form ──────────────────────────────── */
    'Edit Rule'                                                             => '编辑规则',
    'Add Rule'                                                              => '添加规则',
    'Update succeeded'                                                      => '更新成功',
    'Update failed'                                                         => '更新失败',
    'Common Settings'                                                       => '通用设置',
    'Rule Name'                                                             => '规则名称',
    'e.g. Home WAN DDNS'                                                    => '例如：Home WAN DDNS',
    'A descriptive label for this rule.'                                    => '为此规则输入一个描述性标签。',
    'e.g. home.example.com'                                                 => '例如：home.example.com',
    'Fully-qualified domain name (FQDN) to update.'                        => '需要更新的完全限定域名（FQDN）。',
    'TTL (seconds)'                                                         => 'TTL（秒）',
    'Use 1 for automatic TTL. Range: 60–86400 s. Alibaba Cloud DNS minimum is 600 s.'
                                                                            => '使用 1 表示自动 TTL。范围：60–86400 秒。阿里云 DNS 最低为 600 秒。',
    'Hold Ctrl (Windows/Linux) or ⌘ (Mac) to select multiple interfaces. Each interface IP will be kept as a DNS record.'
                                                                            => '按住 Ctrl（Windows/Linux）或 ⌘（Mac）可多选接口。每个接口的 IP 将作为 DNS 记录保存。',
    'Record Types'                                                          => '记录类型',
    'A (IPv4)'                                                              => 'A（IPv4）',
    'AAAA (IPv6)'                                                           => 'AAAA（IPv6）',
    'Select which DNS record types to keep in sync. A = IPv4, AAAA = IPv6. You may select both for dual-stack hosts.'
                                                                            => '选择需要同步的 DNS 记录类型。A = IPv4，AAAA = IPv6。双栈主机可同时选择两者。',
    'Interfaces without an address of the selected type are silently skipped.'
                                                                            => '没有所选类型地址的接口将被自动跳过。',
    'DNS Provider'                                                          => 'DNS 服务提供商',
    'Select the DNS provider that hosts this hostname.'                     => '选择托管此主机名的 DNS 服务提供商。',
    'Force Update'                                                          => '强制更新',
    'Immediately push current interface IPs to the DNS provider'           => '立即将当前接口 IP 推送至 DNS 服务提供商',

    /* ── mwddns_edit.php – validation errors ────────────────────────────── */
    'Rule name is required.'                                                => '规则名称为必填项。',
    'Hostname must be a valid fully-qualified domain name.'                 => '主机名必须是有效的完全限定域名（FQDN）。',
    'TTL must be 1 (auto) or between 60 and 86400 seconds.'                => 'TTL 必须为 1（自动）或在 60 至 86400 秒之间。',
    'At least one interface must be selected.'                              => '至少需要选择一个接口。',
    'At least one record type (A or AAAA) must be selected.'               => '至少需要选择一种记录类型（A 或 AAAA）。',
    'Invalid record type selected.'                                         => '所选记录类型无效。',
    'Invalid DNS provider selected.'                                        => '所选 DNS 服务商无效。',
    'Invalid request token. Please reload the page and try again.'              => '请求令牌无效。请刷新页面后重试。',

    /* ── mwddns.widget.php – dashboard widget ───────────────────────────── */
    'Interface / IP'                                                        => '接口 / IP',
    'Updated'                                                               => '更新时间',
    'No MWDDNS rules configured.'                                           => '未配置 MWDDNS 规则。',
    'Add one'                                                               => '添加规则',
    'Manage rules'                                                          => '管理规则',
    'In sync'                                                               => '已同步',
    'Out of sync'                                                           => '未同步',
    'Err'                                                                   => '错误',
    'Manage Rules'                                                          => '管理规则',

    /* ── cloudflare.php ─────────────────────────────────────────────────── */
    'Cloudflare API Token with DNS edit permission'
                                                                            => '具有 DNS 编辑权限的 Cloudflare API 令牌',
    'Create a token at Cloudflare Dashboard → My Profile → API Tokens with Zone → DNS → Edit permission.'
                                                                            => '在 Cloudflare 控制台 → 个人资料 → API 令牌中创建令牌，授予 Zone → DNS → 编辑权限。',
    "Tokens are stored in plain text in pfSense's config.xml. Restrict the token to only the required zone and permission."
                                                                            => '令牌以明文形式存储于 pfSense 的 config.xml 中。请将令牌权限限定为所需的区域和操作。',
    '32-character hex string'                                               => '32 位十六进制字符串',
    'Found in Cloudflare Dashboard → (select domain) → Overview → Zone ID.'
                                                                            => '在 Cloudflare 控制台 → （选择域名）→ 概览 → Zone ID 中查看。',
    'Cloudflare Proxy (orange cloud)'                                       => 'Cloudflare 代理（橙云）',
    'When enabled, traffic is proxied through Cloudflare CDN. TTL is forced to "auto" by Cloudflare.'
                                                                            => '启用后，流量将通过 Cloudflare CDN 代理。Cloudflare 会强制将 TTL 设置为"自动"。',
    'Cloudflare API token is required.'                                     => 'Cloudflare API 令牌为必填项。',
    'Cloudflare Zone ID must be a 32-character hexadecimal string.'         => 'Cloudflare Zone ID 必须是 32 位十六进制字符串。',

    /* ── alidns.php ─────────────────────────────────────────────────────── */
    'Endpoint: China mainland (alidns.aliyuncs.com)'                       => '端点：中国大陆（alidns.aliyuncs.com）',
    'Endpoint: International / Asia Pacific (alidns.ap-southeast-1.aliyuncs.com)'
                                                                            => '端点：国际/亚太地区（alidns.ap-southeast-1.aliyuncs.com）',
    'Alibaba Cloud AccessKey ID'                                            => '阿里云 AccessKey ID',
    'Found in Alibaba Cloud Console → AccessKey Management.'               => '在阿里云控制台 → AccessKey 管理中查看。',
    'Alibaba Cloud AccessKey Secret'                                        => '阿里云 AccessKey Secret',
    'Keep secret. Stored in plain text in pfSense config.xml. Use a RAM sub-account with only DNS permissions.'
                                                                            => '请妥善保管。以明文形式存储于 pfSense config.xml 中。建议使用仅具有 DNS 权限的 RAM 子账号。',
    'Root Domain'                                                           => '根域名',
    'e.g. example.com'                                                      => '例如：example.com',
    'The root domain registered in Alibaba Cloud DNS. The subdomain prefix (RR) is derived automatically from the Hostname field.'
                                                                            => '在阿里云 DNS 中注册的根域名。子域名前缀（RR）将根据主机名字段自动推导。',
    'Alibaba Cloud AccessKey ID is required.'                               => '阿里云 AccessKey ID 为必填项。',
    'Alibaba Cloud AccessKey Secret is required.'                           => '阿里云 AccessKey Secret 为必填项。',
    'Root Domain must be a valid domain name (e.g. example.com).'          => '根域名必须是有效的域名（例如：example.com）。',

    /* ── aliesa.php ─────────────────────────────────────────────────────── */
    'Found in Alibaba Cloud Console → AccessKey Management. Use a RAM sub-account with ESA DNS permissions only.'
                                                                            => '在阿里云控制台 → AccessKey 管理中查看。建议使用仅具有 ESA DNS 权限的 RAM 子账号。',
    'Keep secret. Stored in plain text in pfSense config.xml.'             => '请妥善保管。以明文形式存储于 pfSense config.xml 中。',
    'ESA Site ID'                                                           => 'ESA 站点 ID',
    'e.g. 123456789'                                                        => '例如：123456789',
    'Numeric Site ID from Alibaba Cloud ESA Console → Sites → (select site) → Site ID.'
                                                                            => '在阿里云 ESA 控制台 → 站点 → （选择站点）→ 站点 ID 中查看。',
    'ESA Site ID must be a numeric value.'                                  => 'ESA 站点 ID 必须为数字。',

    /* ── powerdns.php ───────────────────────────────────────────────────── */
    'API Server URL'                                                        => 'API 服务器 URL',
    'e.g. http://192.168.1.1:8081'                                          => '例如：http://192.168.1.1:8081',
    'Base URL of the PowerDNS HTTP API, without a trailing slash. Include the port if non-standard (default 8081 for authoritative server).'
                                                                            => 'PowerDNS HTTP API 的基础 URL，末尾不加斜杠。如使用非标准端口，请包含端口号（权威服务器默认端口为 8081）。',
    'API Key'                                                               => 'API 密钥',
    'PowerDNS API key'                                                      => 'PowerDNS API 密钥',
    'Set via api-key= in pdns.conf. Sent as the X-API-Key HTTP header. Stored in plain text in pfSense config.xml.'
                                                                            => '通过 pdns.conf 中的 api-key= 设置。以 X-API-Key HTTP 标头发送。以明文形式存储于 pfSense config.xml 中。',
    'Server ID'                                                             => '服务器 ID',
    'PowerDNS server identifier (almost always "localhost"). Leave blank to use the default.'
                                                                            => 'PowerDNS 服务器标识符（几乎始终为 "localhost"）。留空则使用默认值。',
    'Zone Name'                                                             => '区域名称',
    'The authoritative zone name in PowerDNS that contains the hostname to update. Do not include a trailing dot.'
                                                                            => 'PowerDNS 中包含待更新主机名的权威区域名称。末尾不加点号。',
    'PowerDNS API Server URL is required.'                                  => 'PowerDNS API 服务器 URL 为必填项。',
    'PowerDNS API Server URL must start with http:// or https://.'         => 'PowerDNS API 服务器 URL 必须以 http:// 或 https:// 开头。',
    'PowerDNS API Key is required.'                                         => 'PowerDNS API 密钥为必填项。',
    'PowerDNS Zone Name must be a valid domain name (e.g. example.com).'   => 'PowerDNS 区域名称必须是有效的域名（例如：example.com）。',
];

<?php
/*
 * mwddns/locale/zh_HK.php – Traditional Chinese (繁體中文・香港政府用詞標準)
 *
 * Placed at: /usr/local/pkg/mwddns/locale/zh_HK.php
 *
 * Used by mwddns_t() in mwddns.inc when pfSense system language is zh_TW
 * or zh_HK.  Terminology follows the Hong Kong Government's standard
 * Chinese glossary for IT/internet concepts:
 *   伺服器 (server), 介面 (interface), 供應商 (provider),
 *   儲存 (save), 新增 (add), 設定 (configure/settings),
 *   API 金鑰 (API key/token), 網域 (domain), 明文 (plain text), etc.
 *
 * Keys are the original English strings; values are the translations.
 * Strings not listed here fall back to the original English.
 */

return [

    /* ── Shared labels ──────────────────────────────────────────────────── */
    'Services'                   => '服務',
    'Multi-WAN DDNS'             => 'Multi-WAN DDNS',
    'Name'                       => '名稱',
    'Provider'                   => '供應商',
    'Hostname'                   => '主機名稱',
    'Interfaces'                 => '介面',
    'Add'                        => '新增',
    'Edit'                       => '編輯',
    'Delete'                     => '刪除',
    'Save'                       => '儲存',
    'Cancel'                     => '取消',
    'Status'                     => '狀態',
    'Actions'                    => '動作',
    'Error'                      => '錯誤',
    'Never'                      => '從未',
    'Configuration'              => '設定',

    /* ── mwddns.php – list page ─────────────────────────────────────────── */
    'Rule saved successfully.'                                              => '規則已成功儲存。',
    'Rule deleted.'                                                         => '規則已刪除。',
    'DNS records updated successfully.'                                     => 'DNS 記錄已成功更新。',
    'DNS update completed with errors. Check individual rule status.'       => 'DNS 更新已完成，但出現錯誤。請檢查各規則狀態。',
    'Multi-WAN DDNS Rules'                                                  => '多廣域網 DDNS 規則',
    'Interfaces / Current IPs'                                              => '介面 / 現時 IP',
    'Last Updated'                                                          => '最後更新',
    'No rules configured. Click'                                            => '未設定規則。點擊',
    'to create one.'                                                        => '以建立規則。',
    'DNS record matches this IP'                                            => 'DNS 記錄與此 IP 相符',
    'DNS record does NOT contain this IP'                                   => 'DNS 記錄不包含此 IP',
    'No IPv4'                                                               => '無 IPv4',
    'No IPv6'                                                               => '無 IPv6',
    'Delete this rule?'                                                     => '確認刪除此規則？',

    /* ── mwddns_edit.php – edit / add form ──────────────────────────────── */
    'Edit Rule'                                                             => '編輯規則',
    'Add Rule'                                                              => '新增規則',
    'Update succeeded'                                                      => '更新成功',
    'Update failed'                                                         => '更新失敗',
    'Common Settings'                                                       => '通用設定',
    'Rule Name'                                                             => '規則名稱',
    'e.g. Home WAN DDNS'                                                    => '例如：Home WAN DDNS',
    'A descriptive label for this rule.'                                    => '為此規則輸入描述性標籤。',
    'e.g. home.example.com'                                                 => '例如：home.example.com',
    'Fully-qualified domain name (FQDN) to update.'                        => '需要更新的完整網域名稱（FQDN）。',
    'TTL (seconds)'                                                         => 'TTL（秒）',
    'Use 1 for automatic TTL. Range: 60–86400 s. Alibaba Cloud DNS minimum is 600 s.'
                                                                            => '使用 1 表示自動 TTL。範圍：60–86400 秒。阿里雲 DNS 最低為 600 秒。',
    'Hold Ctrl (Windows/Linux) or ⌘ (Mac) to select multiple interfaces. Each interface IP will be kept as a DNS record.'
                                                                            => '按住 Ctrl（Windows/Linux）或 ⌘（Mac）可多選介面。每個介面的 IP 將作為 DNS 記錄儲存。',
    'Record Types'                                                          => '記錄類型',
    'A (IPv4)'                                                              => 'A（IPv4）',
    'AAAA (IPv6)'                                                           => 'AAAA（IPv6）',
    'Select which DNS record types to keep in sync. A = IPv4, AAAA = IPv6. You may select both for dual-stack hosts.'
                                                                            => '選擇需要同步的 DNS 記錄類型。A = IPv4，AAAA = IPv6。雙棧主機可同時選擇兩者。',
    'Interfaces without an address of the selected type are silently skipped.'
                                                                            => '如無所選類型位址的介面將被自動略過。',
    'DNS Provider'                                                          => 'DNS 供應商',
    'Select the DNS provider that hosts this hostname.'                     => '選擇托管此主機名稱的 DNS 供應商。',
    'Force Update'                                                          => '強制更新',
    'Immediately push current interface IPs to the DNS provider'           => '即刻將現時介面 IP 推送至 DNS 供應商',

    /* ── mwddns_edit.php – validation errors ────────────────────────────── */
    'Rule name is required.'                                                => '規則名稱為必填項目。',
    'Hostname must be a valid fully-qualified domain name.'                 => '主機名稱必須是有效的完整網域名稱（FQDN）。',
    'TTL must be 1 (auto) or between 60 and 86400 seconds.'                => 'TTL 必須為 1（自動）或介乎 60 至 86400 秒之間。',
    'At least one interface must be selected.'                              => '至少須選擇一個介面。',
    'At least one record type (A or AAAA) must be selected.'               => '至少須選擇一種記錄類型（A 或 AAAA）。',
    'Invalid record type selected.'                                         => '所選記錄類型無效。',
    'Invalid DNS provider selected.'                                        => '所選 DNS 供應商無效。',
    'Invalid request token. Please reload the page and try again.'              => '請求權杖無效。請重新載入頁面後再試。',

    /* ── mwddns.widget.php – dashboard widget ───────────────────────────── */
    'Interface / IP'                                                        => '介面 / IP',
    'Updated'                                                               => '更新時間',
    'No MWDDNS rules configured.'                                           => '尚未設定 MWDDNS 規則。',
    'Add one'                                                               => '新增規則',
    'Manage rules'                                                          => '管理規則',
    'In sync'                                                               => '已同步',
    'Out of sync'                                                           => '未同步',
    'Err'                                                                   => '錯誤',
    'Manage Rules'                                                          => '管理規則',

    /* ── cloudflare.php ─────────────────────────────────────────────────── */
    'Cloudflare API Token with DNS edit permission'
                                                                            => '具有 DNS 編輯權限的 Cloudflare API 金鑰',
    'Create a token at Cloudflare Dashboard → My Profile → API Tokens with Zone → DNS → Edit permission.'
                                                                            => '需在 Cloudflare 控制台 → 個人資料 → API 金鑰中建立金鑰，授予 Zone → DNS → 編輯權限。',
    "Tokens are stored in plain text in pfSense's config.xml. Restrict the token to only the required zone and permission."
                                                                            => '金鑰以明文形式儲存於 pfSense 的 config.xml 中。請將金鑰權限限定為所需的區域及操作。',
    '32-character hex string'                                               => '32 位十六進制字串',
    'Found in Cloudflare Dashboard → (select domain) → Overview → Zone ID.'
                                                                            => '在 Cloudflare 控制台 → （選擇網域）→ 概覽 → Zone ID 中查看。',
    'Cloudflare Proxy (orange cloud)'                                       => 'Cloudflare 代理（橙雲）',
    'When enabled, traffic is proxied through Cloudflare CDN. TTL is forced to "auto" by Cloudflare.'
                                                                            => '啟用後，流量將透過 Cloudflare CDN 代理。Cloudflare 會強制將 TTL 設定為「自動」。',
    'Cloudflare API token is required.'                                     => 'Cloudflare API 金鑰為必填項目。',
    'Cloudflare Zone ID must be a 32-character hexadecimal string.'         => 'Cloudflare Zone ID 必須是 32 位十六進制字串。',

    /* ── alidns.php ─────────────────────────────────────────────────────── */
    'Endpoint: China mainland (alidns.aliyuncs.com)'                       => '端點：中國大陸（alidns.aliyuncs.com）',
    'Endpoint: International / Asia Pacific (alidns.ap-southeast-1.aliyuncs.com)'
                                                                            => '端點：國際／亞太地區（alidns.ap-southeast-1.aliyuncs.com）',
    'Alibaba Cloud AccessKey ID'                                            => '阿里雲 AccessKey ID',
    'Found in Alibaba Cloud Console → AccessKey Management.'               => '在阿里雲控制台 → AccessKey 管理中查看。',
    'Alibaba Cloud AccessKey Secret'                                        => '阿里雲 AccessKey Secret',
    'Keep secret. Stored in plain text in pfSense config.xml. Use a RAM sub-account with only DNS permissions.'
                                                                            => '請妥善保管。以明文形式儲存於 pfSense config.xml 中。建議使用僅具有 DNS 權限的 RAM 子帳號。',
    'Root Domain'                                                           => '根網域',
    'e.g. example.com'                                                      => '例如：example.com',
    'The root domain registered in Alibaba Cloud DNS. The subdomain prefix (RR) is derived automatically from the Hostname field.'
                                                                            => '在阿里雲 DNS 中登記的根網域。子網域前綴（RR）將根據主機名稱欄位自動推導。',
    'Alibaba Cloud AccessKey ID is required.'                               => '阿里雲 AccessKey ID 為必填項目。',
    'Alibaba Cloud AccessKey Secret is required.'                           => '阿里雲 AccessKey Secret 為必填項目。',
    'Root Domain must be a valid domain name (e.g. example.com).'          => '根網域必須是有效的網域名稱（例如：example.com）。',

    /* ── aliesa.php ─────────────────────────────────────────────────────── */
    'Found in Alibaba Cloud Console → AccessKey Management. Use a RAM sub-account with ESA DNS permissions only.'
                                                                            => '在阿里雲控制台 → AccessKey 管理中查看。建議使用僅具有 ESA DNS 權限的 RAM 子帳號。',
    'Keep secret. Stored in plain text in pfSense config.xml.'             => '請妥善保管。以明文形式儲存於 pfSense config.xml 中。',
    'ESA Site ID'                                                           => 'ESA 站點 ID',
    'e.g. 123456789'                                                        => '例如：123456789',
    'Numeric Site ID from Alibaba Cloud ESA Console → Sites → (select site) → Site ID.'
                                                                            => '在阿里雲 ESA 控制台 → 站點 → （選擇站點）→ 站點 ID 中查看。',
    'ESA Site ID must be a numeric value.'                                  => 'ESA 站點 ID 必須為數字。',

    /* ── powerdns.php ───────────────────────────────────────────────────── */
    'API Server URL'                                                        => 'API 伺服器 URL',
    'e.g. http://192.168.1.1:8081'                                          => '例如：http://192.168.1.1:8081',
    'Base URL of the PowerDNS HTTP API, without a trailing slash. Include the port if non-standard (default 8081 for authoritative server).'
                                                                            => 'PowerDNS HTTP API 的基礎 URL，末尾無需斜線。如使用非標準端口，請包含端口號（權威伺服器預設端口為 8081）。',
    'API Key'                                                               => 'API 金鑰',
    'PowerDNS API key'                                                      => 'PowerDNS API 金鑰',
    'Set via api-key= in pdns.conf. Sent as the X-API-Key HTTP header. Stored in plain text in pfSense config.xml.'
                                                                            => '透過 pdns.conf 中的 api-key= 設定。以 X-API-Key HTTP 標頭傳送。以明文形式儲存於 pfSense config.xml 中。',
    'Server ID'                                                             => '伺服器 ID',
    'PowerDNS server identifier (almost always "localhost"). Leave blank to use the default.'
                                                                            => 'PowerDNS 伺服器識別符（幾乎始終為 "localhost"）。留空則使用預設值。',
    'Zone Name'                                                             => '區域名稱',
    'The authoritative zone name in PowerDNS that contains the hostname to update. Do not include a trailing dot.'
                                                                            => 'PowerDNS 中包含待更新主機名稱的權威區域名稱。末尾不加點號。',
    'PowerDNS API Server URL is required.'                                  => 'PowerDNS API 伺服器 URL 為必填項目。',
    'PowerDNS API Server URL must start with http:// or https://.'         => 'PowerDNS API 伺服器 URL 必須以 http:// 或 https:// 開頭。',
    'PowerDNS API Key is required.'                                         => 'PowerDNS API 金鑰為必填項目。',
    'PowerDNS Zone Name must be a valid domain name (e.g. example.com).'   => 'PowerDNS 區域名稱必須是有效的網域名稱（例如：example.com）。',
];

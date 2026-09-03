# FormTools 3.1.1 client-side unauthorized page_titles write leads to Smarty template injection (SSTI)

## Summary

Clients::updateClientSettingsTab() (Clients.class.php:627-641) unconditionally persists page_titles (bypassing may_edit_page_titles), so a low-privileged client can write it via page_settings.php; the same request (line 61) renders it with General::evalSmartyString on an unsecured Smarty 3.1.31, where {fetch} reads arbitrary files (including global/config.php) and {include_php} can execute server PHP, yielding SSTI.

This issue is distinct from CVE-2024-22722, which concerns a high-privilege Group Name SSTI under the administrative Add Forms functionality. It is also distinct from CVE-2024-6936, which concerns the administrator Setting Handler and the Page Theme argument.The present issue is reachable by an authenticated low-privilege clientthrough the client account settings endpoint and affects the page_titles account setting even when may_edit_page_titles is explicitly disabled.

## Details

Clients::updateClientSettingsTab (Clients.class.php:627-641) writes POST-supplied page_titles/footer_text/max_failed_login_attempts into account_settings without checking may_edit_page_titles. The entry /clients/account/index.php (checkAuth('client')) loads page_settings.php:16-18, so a client submitting update_account_settings=1&page=settings&page_titles=<payload> persists the value, and page_settings.php:61 renders it in the same response with General::evalSmartyString (General.class.php:362-382 uses Templates::getBasicSmarty, an unsecured Smarty/SmartyBC 3.1.31, with eval.tpl {eval} compiling the user string as a template). {fetch file='...'} reads arbitrary files; {include_php file='...'} has PHP-execution capability. Chain: page_settings.php:16-18 submit -> Clients.class.php:627-641 persist -> page_settings.php:61 evalSmartyString -> template execution.

Core vulnerable code path:

```php
// global/code/Clients.class.php:627-641
$settings = array();
if (isset($info["page_titles"])) { $settings["page_titles"] = $info["page_titles"]; }
if (isset($info["footer_text"])) { $settings["footer_text"] = $info["footer_text"]; }
if (isset($info["max_failed_login_attempts"])) { $settings["max_failed_login_attempts"] = $info["max_failed_login_attempts"]; }
if (!empty($settings)) { Accounts::setAccountSettings($account_id, $settings); }
```

Trust-boundary failure: updateClientSettingsTab unconditionally persists page_titles, bypassing the may_edit_page_titles permission flag.

```php
// clients/account/page_settings.php:16-61
if (isset($request["update_account_settings"])) { $request["page"]="settings"; Clients::updateClient($account_id,$request); }
...
"head_title" => General::evalSmartyString(Sessions::get("account.settings.page_titles"), array("page" => $LANG["phrase_account_settings"])),
```

Entry and trigger: after saving, the same request renders page_titles via evalSmartyString, so SSTI fires immediately.

## POC

Preconditions: Any logged-in FormTools account (client or admin) can perform this action. When a client submits the request, they must include the mandatory configuration fields they have permission to edit (such as `theme`, `logout_url`, `ui_language`, or `timezone_offset`, with valid default values) to pass server-side `validate_fields` checks; admins are not required to include these fields. There are no special conditions other than the standard CSRF protection requirements.

1) POST /clients/account/index.php with page=settings&update_account_settings=1&page_titles={fetch file='/etc/passwd'}; expected: response reflects /etc/passwd. 
<img width="1849" height="1035" alt="image" src="https://github.com/user-attachments/assets/7c43f736-93b7-49b3-a811-2d9c9292cbe7" />
<img width="2570" height="1367" alt="image" src="https://github.com/user-attachments/assets/0b07e8c1-0beb-4ec3-a2de-da33b3c557e0" />

2) Point fetch at global/config.php to read DB credentials; {include_php file='...'} may execute server PHP if allowed.
<img width="2567" height="1381" alt="image" src="https://github.com/user-attachments/assets/fc30e145-120f-487a-80c3-257b061b1f23" />
<img width="995" height="520" alt="image" src="https://github.com/user-attachments/assets/12c59836-56eb-428b-b5b5-f89cae733801" />


## Impact

A low-privileged client can bypass the may_edit_page_titles flag, persist attacker template content, and have it executed by an unsecured Smarty 3.1.31 engine: {fetch} yields arbitrary file read (DB credentials/source), {include_php} can escalate to PHP execution.

## Remediation

Gate fields by may_edit_page_titles permission; treat page_titles as plain text; enable Smarty security mode and disable {fetch}/{include_php} in evalSmartyString.

## Supplemental Information

### Affected products

- Vendor / project: Form Tools Core
- Repository: https://github.com/formtools/core
- Issue：https://github.com/formtools/core/issues/956
- Package name: formtools
- Affected versions: 3.1.1
- Patched versions: none confirmed

### Vulnerability type

- Server Side Template Injection (SSTI)
- CWE: CWE-1336 Server-Side Template Injection
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

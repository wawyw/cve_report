# xcms sendFindPwdMail email parameter SQL injection

## Summary

The Admin console of xcms (a ThinkPHP 3.2.2 based CMS) exposes PublicController::sendFindPwdMail() (Admin/Home/Controller/PublicController.class.php:92-121) without authentication: the 'Public' controller is exempted from login and RBAC (NOT_LOGIN_MODULES/NOT_AUTH_MODULE='Public' in Admin/Common/Conf/security_config.php), and the action performs no captcha, CSRF-token or rate-limit check. The endpoint forwards the unfiltered $_POST['admin']['email'] to AdminService::existAccount() (Admin/Home/Service/AdminService.class.php:200-206), which executes where("email='{$email}'")->count() with a string where clause that ThinkPHP Db::parseWhere() appends verbatim. An unauthenticated attacker can therefore run blind SQL injection. A reliable boolean oracle exists: a false predicate returns '登录用户不存在！' while a true predicate proceeds to smtp_mail(), which fails with the default SMTP host (smtp.example.com) and returns '系统发生错误'; time-based payloads work regardless of SMTP state. This enables reading qt_admin (administrator emails and md5-based password hashes) and other database content, and can be chained with other Public-module weaknesses (e.g. the empty mail_hash password reset) for account takeover.

## Details

Root cause and trust-boundary failure.

The xcms Admin application (entry qt-admin.php) authenticates most controllers through CommonController::_initialize(), which enforces login for every controller except those listed in NOT_LOGIN_MODULES. The application configuration Admin/Common/Conf/security_config.php defines both NOT_LOGIN_MODULES and NOT_AUTH_MODULE as 'Public', and Rbac::AccessDecision() returns true for modules in NOT_AUTH_MODULE without requiring a session. Consequently every action of PublicController — including sendFindPwdMail() — is reachable by unauthenticated remote callers. PublicController::_initialize() additionally enables the form token only for the 'index' action (TOKEN_ON), so sendFindPwdMail() has no token protection, no captcha and no rate limiting.

The vulnerable flow (Admin/Home/Controller/PublicController.class.php:92-121):

1. Source: the attacker fully controls $_POST['admin']['email'] (no filtering or validation is applied to the raw POST value).
2. The controller calls $adminService->existAccount($_POST['admin']['email']). Inside AdminService::existAccount() (Admin/Home/Service/AdminService.class.php:200-206) the value is concatenated into a single-quoted string WHERE: $this->getM()->where("email='{$email}'")->count() > 0.
3. Sink: ThinkPHP Db::parseWhere() treats string where values as final SQL (it is appended verbatim with no escaping or prepared-statement binding), so closing the quote with a single quote lets the attacker control the WHERE predicate of SELECT COUNT(*) FROM qt_admin.
4. Oracle: the boolean result is observable. If the injected predicate is false, existAccount() returns false and the controller responds with {"status":false,"info":"登录用户不存在！"}. If it is true, the flow continues; with the shipped default SMTP configuration (Admin/Common/Conf/mail_config.php: SMTP_HOST=smtp.example.com, which cannot deliver mail), smtp_mail() fails and the response is {"status":false,"info":"系统出错了，请稍后再试！"}. These two distinguishable responses form a stable boolean oracle for blind extraction. Time-based payloads (SLEEP) work independently of SMTP state.

Trust-boundary summary: a security-sensitive password-recovery endpoint was placed under a 'Public' (unauthenticated) module and concatenates attacker input into a string SQL condition. This is an application-level SQL injection: unfiltered user input flowing into a raw string where clause that the framework forwards verbatim to MySQL.

Core vulnerable code path:

```php
// Admin/Home/Controller/PublicController.class.php:92-121
public function sendFindPwdMail() {
    $adminService = D('Admin', 'Service');
    if (!isset($_POST['admin']['email'])
        || !$adminService->existAccount($_POST['admin']['email'])) {
        return $this->errorReturn('登录用户不存在！');
    }

    $email = $_POST['admin']['email'];
    $admin = M('Admin')->getByEmail($email);
    $randCode = rand_code(5);
    $hash = $admin['id'] . md5($randCode);

    $config = C('MAIL');
    $target = U('Public/findPassword', array('hash' => $hash));
    $url = $_SERVER['HTTP_HOST'] . $target;
    $body = str_replace('?', $url, $config['MAIL_BODY']);

    // 发送邮件
    $result = smtp_mail($email, $email, C('SITE_TITLE'), $body, $config);

    if (true !== $result) {
        return $this->errorReturn('系统出错了，请稍后再试！');
    }

    $admin['mail_hash'] = $hash;
    M('Admin')->save($admin);

    $info = "密码重置邮件已发，请到{$admin['email']}查收！";
    return $this->successReturn($info);
}
```

Unauthenticated entry point of the Admin application: PublicController is exempted from login and RBAC (security_config.php sets NOT_LOGIN_MODULES and NOT_AUTH_MODULE to 'Public'), and sendFindPwdMail() has no server-side captcha, CSRF token or rate limit. The attacker-controlled $_POST['admin']['email'] is forwarded to AdminService::existAccount(); depending on the SQL result the code either returns '登录用户不存在！' immediately or continues to smtp_mail(), which fails against the default SMTP host (smtp.example.com) and returns '系统出错了，请稍后再试！'. That response difference is a reliable boolean oracle for blind injection.

```php
// Admin/Home/Service/AdminService.class.php:200-206
public function existAccount($email) {
    if ($this->getM()->where("email='{$email}'")->count() > 0) {
        return true;
    }

    return false;
}
```

The actual injection sink: AdminService::existAccount() concatenates the unfiltered email value into a single-quoted string WHERE clause (email='{$email}') and runs count() against the qt_admin table. ThinkPHP Db::parseWhere() returns string where clauses verbatim with no escaping or parameter binding, so an attacker who closes the quote controls the SQL predicate; the boolean result is then reflected in the response difference described above.

## POC

Preconditions:

- The Admin entry qt-admin.php is reachable.
- Boolean oracle: with the default (unusable) SMTP configuration (SMTP_HOST=smtp.example.com in Admin/Common/Conf/mail_config.php), a true injection condition continues to smtp_mail() which fails and yields the '系统发生错误' response, whereas a false condition returns '登录用户不存在！' immediately. If a working SMTP server is configured in production, use a time-based payload instead.

Reproduction steps:

1. Confirm the boolean oracle.
   Method: POST
   Endpoint: /qt-admin.php/Public/sendFindPwdMail
   Headers: Content-Type: application/x-www-form-urlencoded
   Body (true case): admin[email]=x' OR 1 AND '1'='1
   Body (false case): admin[email]=x' OR 0 AND '1'='1
   Expected result: the true case returns "系统发生错误"; the false case returns {"status":false,"info":"登录用户不存在！"}. The two responses reliably encode the truth value of the injected predicate.
<img width="3456" height="1519" alt="image" src="https://github.com/user-attachments/assets/1c0d6d37-b458-4562-a9aa-3b31856a934a" />
<img width="3462" height="1655" alt="image" src="https://github.com/user-attachments/assets/36f0b2b0-5c88-4b01-9089-feee4262ab63" />

2. Extract data character by character with boolean/conditional payloads, e.g. for each position i and character guess c:
   admin[email]=x' OR (SELECT SUBSTRING(password,i,1)='c' FROM qt_admin WHERE id=1) AND '1'='1
   Expected result: true/false responses discriminate each guessed character; recover the full administrator email and md5-based password hash from qt_admin.

3. Alternative time-based confirmation (usable with any SMTP configuration):
   Body: admin[email]=x' OR SLEEP(5) AND '1'='1
   Expected result: the response is delayed by about 5 seconds when the injected predicate executes SLEEP(5).
<img width="2468" height="1083" alt="image" src="https://github.com/user-attachments/assets/ac3c2325-3c4c-4e8f-8afb-eb35f79ed2a9" />
<img width="2464" height="1079" alt="image" src="https://github.com/user-attachments/assets/e13251fe-fe33-4def-a6dc-4fb574d86f76" />


## Impact

An unauthenticated remote attacker can execute boolean- or time-based blind SQL injection through the public password-recovery mail endpoint of the Admin console, reading the entire qt_admin table (administrator emails and md5-based password hashes) as well as any other data in the application database. Because the same 'Public' module also exposes the resetPassword flow, the disclosed administrator hashes/accounts can be combined with other weaknesses (e.g. the empty mail_hash reset defect) to take over administrator accounts. The flaw primarily breaks confidentiality of the database and, depending on the privileges of the MySQL account and available SMTP configuration, can support further account-takeover or file-write escalation.

## Remediation

1) Replace the string WHERE in AdminService::existAccount() with an array condition or a parameterized query: where(array('email'=>$email)).
2) Never rely on response wording as an oracle: make the error message identical whether or not the account exists.
3) Add a captcha and strict rate limiting to sendFindPwdMail() (it currently has neither) and log all requests.
4) Apply server-side input filtering/validation for the email parameter (format + length) before it reaches any SQL operation.
5) Run the MySQL account with least privilege (no FILE privilege) and use parameterization throughout the application (forbid string where clauses in Service/Model layers).
6) Treat password-recovery flows as high-risk functions requiring additional controls (token expiry, single-use, bind to a session/email proof).

## Supplemental Information

### Affected products

- Vendor / project: XCMS
- Repository: https://gitee.com/jackq/XCMS
- Issue: https://gitee.com/jackq/XCMS/issues/IKDHE0
- Affected versions: commit 3fab5342cc509945a7ce1b8ec39d19f701b89261
- Patched versions: none confirmed

### Vulnerability type

- SQL Injection
- CWE: CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

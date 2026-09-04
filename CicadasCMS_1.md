# Arbitrary File Write via Backend Template Editing in CicadasCMS (unrestricted filePath)

## Summary

The CicadasCMS backend template editor at /system/cms/template/save writes the request-supplied TemplateFile object (filePath and content) directly to disk: TemplateController.save() performs no validation before calling TemplateFileServiceImpl.writeTemplateFileContent(), which opens new FileOutputStream(new File(filePath)) and writes content verbatim, with no directory whitelist, no canonical-path prefix check, and no rejection of ../ or absolute paths. An authenticated backend user with template:save permission can overwrite classpath templates/configuration files, and in the Servlet-container (WAR) deployments supported by this project can write a .jsp web shell into the web application directory to achieve remote code execution.

## Details

Root cause and trust boundary failure. The template management module is exposed by TemplateController (class-level @RequestMapping("/system/cms/template")). The save handler (TemplateController.java:49-55, @RequiresPermissions("template:save"), POST /system/cms/template/save) passes the Spring-MVC-bound TemplateFile object straight through: save(TemplateFile templateFile) immediately invokes templateFileService.writeTemplateFileContent(templateFile).

The dangerous sink is TemplateFileServiceImpl.writeTemplateFileContent() (TemplateFileServiceImpl.java:108-119). The method applies no directory whitelist, no real-path validation, and no traversal filter to filePath: OutputStream outputStream = new FileOutputStream(new File(templateFile.getFilePath())); followed by os.write(templateFile.getContent()). TemplateFile is a plain data bean (TemplateFile.java) exposing public setters for filePath and content, so both values are fully controllable via HTTP parameters; the read side (findByPath(), 65-73) likewise opens new File(path) directly and can be used by an attacker to probe writable targets.

Trust boundary failure: semantically the feature is only meant to edit template files under the template root (TEMPLATE_PATH = PathUtil.getRootClassPath()+"/templates/www"), but the destination path is fully trusted to client input: the target is not restricted to the template directory, no canonicalPath prefix is checked, and ../ sequences and absolute paths are not filtered. Because the project ships ServletInitializer (WAR packaging supported), a deployment on an external Servlet container lets an attacker point filePath at a .jsp file inside the web application directory and write a web shell, producing an arbitrary file write to RCE chain; the minimum impact is overwriting classpath templates/configuration, damaging integrity and availability.

Core vulnerable code path:

```java
// CicadasCms/src/main/java/com/zhiliao/module/web/cms/TemplateController.java:49-55
@RequiresPermissions("template:save")
    @RequestMapping("/save")
    @ResponseBody
    public String save(TemplateFile templateFile){
        templateFileService.writeTemplateFileContent(templateFile);
        return JsonUtil.toSUCCESS("模板修改成功","template-tab",false);
    }
```

The save handler accepts the Spring-MVC-bound TemplateFile object whose filePath and content are fully controlled by the HTTP request and immediately calls writeTemplateFileContent() with no additional path validation.

```java
// CicadasCms/src/main/java/com/zhiliao/common/template/TemplateFileServiceImpl.java:108-119
@Async
    public  void writeTemplateFileContent(TemplateFile templateFile){
        try {
            OutputStream outputStream = new FileOutputStream(new File(templateFile.getFilePath()));
            OutputStreamWriter os = new OutputStreamWriter(outputStream, "utf-8");
            os.write(templateFile.getContent());
            os.flush();
            os.close();
        }catch (Exception e){
            throw  new SystemException(e.getMessage());
        }
    }
```

The sink performs an unrestricted file write: new FileOutputStream(new File(templateFile.getFilePath())) writes templateFile.getContent() to whatever path the attacker supplied. There is no directory whitelist, no canonical-path prefix check, and no rejection of ../ or absolute paths.

```java
// CicadasCms/src/main/java/com/zhiliao/common/template/TemplateFile.java:8-57
public class TemplateFile {

    private String fileName;

    private String filePath;

    private Boolean isDirectory;

    private String content;

    private List<TemplateFile> childList;
```

TemplateFile is a plain data bean with filePath/content setters, which confirms that both the destination path and the written content are directly bindable from the HTTP request by Spring MVC.

## POC

Preconditions: (1) a backend account that can reach /system/** (login page /admin/login; the Shiro filter chain requires auth + perms["system"]); (2) the account holds the template:save permission (default admin does); (3) the target runtime/deployment directory is writable (development classpath or external Tomcat WAR deployment).

Reproduction steps:

1. Log in to the backend and obtain a valid session (JSESSIONID cookie etc.).

2. POST directly to the template save endpoint, pointing filePath at a JSP file under the web application directory and writing JSP content:
   POST /system/cms/template/save HTTP/1.1
   Host: victim
   Cookie: JSESSIONID=<session>
   Content-Type: application/x-www-form-urlencoded

   filePath=/usr/local/tomcat/webapps/ROOT/2.jsp&content=<%25out.print("test");%25>
   Expected result: response {"code":200,"message":"模板修改成功",...} and the file is written (in external Tomcat deployment).
   <img width="2460" height="975" alt="image" src="https://github.com/user-attachments/assets/efae122a-d9ed-414a-8fb3-7dc228a14f81" />


3. Verify the write:
   GET /2.jsp HTTP/1.1
   Host: victim
   Expected result: result output or server behavior change confirming the arbitrary file write. For jar/embedded-Tomcat targets (JSP not parsed), point filePath at a classpath template or configuration file to verify arbitrary overwrite.
   <img width="701" height="238" alt="image" src="https://github.com/user-attachments/assets/20124eed-8abe-4910-be5c-ba112686547f" />



## Impact

An account with backend template:save permission can write arbitrary content to any writable path on the server: overwriting classpath templates and configuration files breaks application integrity or availability; in Servlet-container (WAR) deployment modes supported by the project (ServletInitializer) a .jsp web shell can be planted under the web directory to obtain remote code execution. This is a standard arbitrary file write to web-shell chain.

## Remediation

1) Server-side, confine template writes to TEMPLATE_PATH (classpath:/templates/www): resolve the canonical path and verify it stays under the template root; reject absolute paths and ../ traversal. 2) Add CSRF token protection and operation auditing to /system/cms/template/save, and review written template content. 3) In external Servlet-container deployments, isolate the template directory from servlet-executable directories and forbid template content from being stored with .jsp/.jspx script extensions. 4) Add regression tests asserting that filePath containing ../ or an absolute path outside the template directory is rejected.

## Supplemental Information

### Affected products

- Vendor / project: CicadasCMS
- Repository: https://gitee.com/westboy/CicadasCMS
- Issue: https://gitee.com/westboy/CicadasCMS/issues/IKDEAM
- Affected versions: commit 2431154dac8d0735e04f1fd2a3c3556668fc8dab
- Patched versions: none confirmed

### Vulnerability type

- Arbitrary File Write
- CWE: CWE-22 Path Traversal / CWE-73 Unrestricted File Write
- Suggested severity: High

### Reporter

Guangzhou University: Wen Youwen, Wang Le


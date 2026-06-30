### 扫描范围
* 扫描整个项目：python scripts/tower_compliance_scan.py . --format text

* 扫描某个文件夹：python scripts/tower_compliance_scan.py ruoyi-admin/src/main/java --format text

* 扫描某个文件：python scripts/tower_compliance_scan.py ruoyi-admin/src/main/resources/application-dev.yml --format text

* 输出 JSON：python scripts/tower_compliance_scan.py <文件或文件夹路径> --format json

### 修改范围
Skill 本身支持让 Codex/Claude 只修改指定文件或文件夹。
你可以这样说：使用 tower-it-compliance 只检查并修复 ruoyi-system/src/main/resources/mapper/jinyu 目录
只扫描 application-dev.yml，列出不合规项，不要修改
只修复 JyScheduleTaskServiceImpl.java 中的 SQL 拼接问题
扫描 ruoyi-admin/src/main/java/com/ruoyi/web/controller/jinyu，并修复高危项

### 注意
扫描脚本只负责发现问题，不会自动改文件。
真正修改由 Codex/Claude 根据扫描结果和规范执行；你可以明确限制“只允许修改某个文件/目录”。

# CrimsonFlux 导出字段

用户可下载 `notes.csv` 与 `notes.jsonl`。二者包含相同的笔记集合，但用途不同：

- `notes.csv` 面向普通用户和表格软件，只保留阅读、筛选内容时有用的列；
- `notes.jsonl` 面向程序处理，保留完整的规范化字段、数组和空值类型；
- `manifest.json` 保存任务来源、完成情况、请求统计和两种文件的校验信息。

CSV 不再重复输出 `schema_version`、`job_id`、`source_type`、`source_query`、`source_page`、`source_rank`。这些任务级或分页级信息仍保留在 JSONL 或 manifest 中，CSV 的行顺序就是原有结果顺序。

## CSV 默认列

固定列按以下顺序出现：

1. `title`、`note_url`、`note_type`、`note_id`；
2. 用户选择的作者、正文、标签、互动和媒体列；
3. `collected_at`、`detail_status`、`detail_error_code`。

未选择的可选信息不会生成空列。

## JSONL 完整字段

| 字段 | 含义 |
|---|---|
| `schema_version` | 导出契约版本 |
| `job_id` | 本地任务 ID |
| `source_type` | `keyword` 或 `user` |
| `source_query` | 关键词或规范化主页 URL |
| `source_page` | 列表页序号 |
| `source_rank` | 去重后的采集顺序 |
| `note_id` | 笔记 ID |
| `note_url` | 已移除认证查询参数的笔记 URL |
| `note_type` | `image`、`video` 或 `unknown` |
| `title` | 标题 |
| `collected_at` | 采集时间 |
| `detail_status` | 详情是否成功、失败或未请求 |
| `detail_error_code` | 公开错误码，不含平台秘密响应 |

## 可选字段组

### 作者

- `author_id`
- `author_name`
- `author_profile_url`

### 正文

- `description`
- `published_at`
- `updated_at`

### 标签

- `tag_names`

### 公开互动计数

- `liked_count`
- `collected_count`
- `comment_count`
- `share_count`

这些是采集时平台接口返回的计数，不是曝光、互动率或官方统计口径。

### 媒体引用

- `image_count`
- `image_urls`
- `has_video`
- `video_url`

产品只保存 URL，不发起图片或视频下载。URL 可能过期。

## 永不导出的字段

- Cookie、`web_session`、`a1`；
- `xsec_token`、签名、Authorization 和请求头；
- 本地文件路径、加密密钥、原始私有 cursor；
- 评论数据和已下载媒体，因为本版本不采集它们。

CSV 会对以 `= + - @`、制表符或回车开头的外部字符串添加安全前缀，降低表格公式注入风险。

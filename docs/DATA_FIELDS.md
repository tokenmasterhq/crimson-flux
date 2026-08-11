# CrimsonFlux 导出字段

用户可下载 `notes.csv` 与 `notes.jsonl`。二者来自同一规范化记录集合；CSV 适合表格软件，JSONL 保留数组和空值类型。

## 核心字段

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

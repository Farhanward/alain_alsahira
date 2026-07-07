# دليل تشغيل alain_alsahira (Operations Runbook)

## 1) التهيئة عبر متغيرات البيئة

| المتغير | الافتراضي | الوظيفة |
|---|---|---|
| `ALAIN_HOME` | جذر المشروع | مجلد الحالة (logs) |
| `ALAIN_API_KEY` | (فارغ = بلا مصادقة) | إن ضُبط: كل `/api/*` عدا health يتطلب `X-API-Key` |
| `ALAIN_HOST` / `ALAIN_PORT` | `127.0.0.1` / `8793` | عنوان الخدمة |
| `ALAIN_MAX_BODY_BYTES` | `1048576` | حد حجم الطلب (413 عند التجاوز) |
| `ALAIN_LOG_DIR` / `ALAIN_LOG_LEVEL` | `<home>\logs` / `INFO` | سجلات JSON منظمة |

## 2) تشغيل الخدمة

```powershell
$env:ALAIN_API_KEY = "مفتاح-قوي"
python -m alain_alsahira.cli serve
```

## 3) نقاط الفحص المشتركة

- `GET /api/health` — مفتوح دائماً (للـ probes): `{ok, service, version, uptime_s, auth_required}`.
- `GET /api/version` — إصدار الخدمة.
- `GET /api/metrics` — عدادات + p50/p95/p99 زمن المعالجة.

نقاط النطاق موثقة في `README.md`.

## 4) السجلات

`logs\alain-alsahira.service.jsonl` — JSON سطري لكل طلب `{path, status, ms}` بتدوير تلقائي 5MB × 3 نسخ.

## 5) الحوادث الشائعة

| العرض | السبب المرجح | العلاج |
|---|---|---|
| `401` لكل الطلبات | مفتاح API غير مطابق | طابق `X-API-Key` مع `ALAIN_API_KEY` |
| `413` | حمولة أكبر من الحد | ارفع `ALAIN_MAX_BODY_BYTES` أو قسّم الطلب |
| بطء p99 | حمولات ضخمة أو موارد مشغولة | راقب `/api/metrics` وقلل حجم الدفعات |

## 6) الترقية

1. أوقف الخدمة → حدّث الكود.
2. `python -m unittest discover -s tests -v` (يجب أن تنجح كلها).
3. أعد التشغيل وتحقق من `/api/health`.

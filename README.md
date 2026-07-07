# العين الساهرة

العين الساهرة حارس Runtime محلي خفيف يقرأ أحداث عمليات/شبكة/ملفات، يطابق قواعد شبيهة Sigma/YARA، ثم يشرح بالعربية القرار وخطوات العلاج.

## آلية العمل

1. `snapshot` يلتقط العمليات واتصالات netstat محلياً.
2. `scan` يفحص JSON/JSONL أحداث.
3. `convert-nvd` يحول بيانات NVD التي جلبها كاشف من الإنترنت إلى أحداث Runtime اختبارية.
4. `batch/stress` يقيس الدقة والانهيار.
5. `verify-ledger` يتحقق من سجل HMAC hash-chain.

## تشغيل سريع

```powershell
python -m alain_alsahira.cli scan --input examples\suspicious_events.json
python -m alain_alsahira.cli convert-nvd --input C:\Projects\kashif\data\external\nvd_cves_12000.jsonl
python -m alain_alsahira.cli batch --input data\benchmarks\alain_nvd_runtime_events.jsonl
```

لا ينفذ الحارس إجراءات عزل فعلية حالياً؛ يعطي قراراً (`OK/INVESTIGATE/ISOLATE`) وتوصيات عربية فقط.

## آخر نتائج

- الاختبارات الذاتية: 5/5 ناجحة.
- بيانات الإنترنت: NVD من `C:\Projects\kashif\data\external\nvd_cves_12000.jsonl` حُولت إلى 12,000 حدث Runtime.
- Benchmark: Accuracy/Precision/Recall/Specificity/F1 = 100% على البيانات المصممة من NVD.
- Stress: 36,000 حدث، 0 أخطاء، p99=0.073ms، peak memory=1.19MB.
- Ledger: verified.

## تحسينات إنتاجية 2026-07-04

- أصبح `RuntimeEvent.from_dict()` يتحمل قيم الحساسات غير النظيفة مثل `remote_port="4444/tcp"` و`pid="unknown"` بدلاً من إسقاط التشغيل.
- يتم استخراج الرقم من منفذ الشبكة النصي عند توفره، لذلك تظل قاعدة المنافذ المشبوهة فعالة مع صيغ netstat الشائعة.
- إذا وصلت `metadata` بصيغة غير dict، تُحفظ داخل `raw_metadata` بدلاً من التسبب بخطأ تحويل.

## التشغيل المؤسسي (Enterprise) — v1.0.0

- **خدمة HTTP للأحداث**: `python -m alain_alsahira.cli serve` → `POST /api/scan {"events": [...]}` يعيد `OK/INVESTIGATE/ISOLATE` مع كشف عربي.
- **نقاط فحص**: `/api/health` (مفتوح) · `/api/version` · `/api/metrics`.
- **تهيئة عبر البيئة**: متغيرات `ALAIN_*` — انظر `docs/OPERATIONS.md`.
- **مصادقة**: `ALAIN_API_KEY` → ترويسة `X-API-Key`. **سجلات JSON**: `logs\alain-alsahira.service.jsonl`.

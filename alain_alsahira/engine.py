from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from .models import Assessment, Detection, RuntimeEvent


RULES: list[tuple[str, str, str, str, str, re.Pattern[str]]] = [
    ("ENCODED_POWERSHELL", "critical", "PowerShell مشفر", "أمر PowerShell مشفر أو مخفي قد يدل على تنفيذ حمولة.", "اعزل العملية وافحص المصدر ودوّر الأسرار.", re.compile(r"powershell(?:\.exe)?.{0,120}(-enc|-encodedcommand|frombase64string)", re.I)),
    ("CREDENTIAL_DUMP", "critical", "محاولة سرقة اعتماديات", "رصد مؤشر Mimikatz/Sekurlsa/Procdump/LSASS.", "افصل الجهاز مؤقتاً واجمع الذاكرة وغيّر كلمات المرور.", re.compile(r"(mimikatz|sekurlsa|procdump.{0,80}lsass|lsass.{0,80}dump)", re.I)),
    ("RECOVERY_TAMPER", "critical", "تعطيل الاسترجاع", "رصد حذف نسخ ظل أو تعطيل الاسترداد.", "أوقف العملية فوراً وتحقق من النسخ الاحتياطية.", re.compile(r"(vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set\s+recoveryenabled\s+no)", re.I)),
    ("SCRIPT_DOWNLOAD_EXEC", "high", "تحميل وتنفيذ سكربت", "تنزيل مباشر متبوع بتنفيذ سكربت.", "امنع الاتصال وافحص الملف المحمل.", re.compile(r"(curl|wget|iwr|invoke-webrequest|certutil).{0,160}(iex|invoke-expression|bash|sh|python\s+-c|urlcache)", re.I)),
    ("LOLBIN_REMOTE", "high", "استخدام LOLBin بعيد", "رصد mshta/regsvr32/rundll32 مع عنوان بعيد.", "راجع العملية والأب الشرعي وأوقفها إن لم تكن معروفة.", re.compile(r"(mshta|regsvr32|rundll32).{0,120}https?://", re.I)),
    ("WEB_SHELL_CHILD", "high", "خادم ويب يستدعي shell", "عملية ويب أنجبت shell أو مفسر أوامر.", "اعزل التطبيق وافحص webroot وسجلات الدخول.", re.compile(r"(nginx|apache|httpd|w3wp|php-fpm).{0,100}(cmd|powershell|bash|sh|python)", re.I)),
    ("SECRET_FILE_ACCESS", "high", "وصول لملف أسرار", "رصد وصول أو مسار يحتوي أسراراً حساسة.", "راجع صلاحيات الملف وانقل السر إلى خزنة.", re.compile(r"(\.env\b|id_rsa|private_key|credentials\.json|docker\.sock)", re.I)),
    ("SUSPICIOUS_PORT", "medium", "منفذ مشبوه", "اتصال أو استماع على منفذ شائع في أدوات تحكم أو اختبار اختراق.", "تحقق من العملية المالكة للمنفذ.", re.compile(r"\b(4444|1337|31337|6667|9001)\b")),
]
SEVERITY_SCORE = {"low": 10, "medium": 25, "high": 45, "critical": 70}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def analyze_events(events: Iterable[RuntimeEvent | dict]) -> Assessment:
    normalized = [event if isinstance(event, RuntimeEvent) else RuntimeEvent.from_dict(event) for event in events]
    detections: list[Detection] = []
    for event in normalized:
        text = event.scan_text()
        if event.parent_process and event.process_name:
            text += f" {event.parent_process} {event.process_name}"
        for rule_id, severity, title, detail, action, pattern in RULES:
            match = pattern.search(text)
            if not match:
                continue
            detections.append(Detection(rule_id, severity, title, detail, match.group(0)[:220], action))
    severity_counts = Counter(item.severity for item in detections)
    risk = min(100, sum(SEVERITY_SCORE.get(item.severity, 10) for item in detections))
    highest = "info"
    for sev in severity_counts:
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[highest]:
            highest = sev
    decision = "ISOLATE" if highest == "critical" or risk >= 80 else "INVESTIGATE" if detections else "OK"
    summary = "لا توجد مؤشرات خطرة." if not detections else f"رُصدت {len(detections)} إشارة، أعلى شدة {highest}، والقرار {decision}."
    return Assessment(len(normalized), detections, risk, highest, decision, summary)

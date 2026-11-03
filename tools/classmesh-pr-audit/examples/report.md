# تقرير جاهزية طلبات ClassMesh

الوضع: **FIXTURE_ONLY** · جمع البيانات: **PARTIAL**

المستودع: owner/project · الفرع المستهدف: main

بداية الفحص: 2026-11-04T02:00:00Z · نهايته: 2026-11-04T02:00:00Z

هذا تقرير للقراءة فقط. READY_FOR_FINAL_REVIEW تعني جاهزية العرض للمراجعة النهائية، وليست إذنًا بالدمج.

## الملخص

إجمالي الطلبات: **4** · الجاهز للمراجعة النهائية: **1**

قد يظهر الطلب في أكثر من تصنيف؛ لا تُجمع الأعداد باعتبارها طلبات مختلفة.

| التصنيف | العدد |
| --- | ---: |
| CI_FAILED | 1 |
| CI_PENDING | 1 |
| DEPENDENCY_BLOCKED | 1 |
| DRAFT | 1 |
| MANUAL_ACCEPTANCE_REQUIRED | 2 |
| MERGE_CONFLICT | 1 |
| READY_FOR_FINAL_REVIEW | 1 |
| SECURITY_REVIEW_REQUIRED | 2 |

## التبعيات وأولوية المراجعة

الترتيب يخص معالجة العوائق والمراجعة، ولا يشغّل أي دمج أو مجدول.

- `#102 → #103`

الأولوية المقترحة (الأساس قبل التابع): `#102 → #104 → #101 → #103`

## #102 — مسودة مع نجاح CI على commit قديم فقط

https://github.com/owner/project/pull/102

**التصنيفات:** DRAFT، CI_PENDING، SECURITY_REVIEW_REQUIRED، MANUAL_ACCEPTANCE_REQUIRED

- أولوية المراجعة: 1
- Draft: True · قابلية الدمج: True · GitHub: clean
- HEAD: `0000000000000000000000000000000000000066` (feature-102)
- Base: main · SHA في PR: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- رأس الفرع الأساسي الحالي: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- التبعيات: CLEAR · الآباء: []

### العوائق

- **DRAFT**: الطلب مسودة ولم يُعرض للمراجعة النهائية (DRAFT)
- **CI_PENDING**: Windows Build: UNKNOWN (CI_INCOMPLETE:Windows Build)
- **CI_PENDING**: Portable Rust: UNKNOWN (CI_INCOMPLETE:Portable Rust)
- **CI_PENDING**: CodeQL: UNKNOWN (CI_INCOMPLETE:CodeQL)
- **SECURITY_REVIEW_REQUIRED**: الفحص الأمني غير ناجح أو غير متاح: CodeQL (SECURITY_CHECK:CodeQL)
- **CI_PENDING**: Gitleaks: UNKNOWN (CI_INCOMPLETE:Gitleaks)
- **SECURITY_REVIEW_REQUIRED**: الفحص الأمني غير ناجح أو غير متاح: Gitleaks (SECURITY_CHECK:Gitleaks)
- **MANUAL_ACCEPTANCE_REQUIRED**: تنقص موافقة مستقلة على HEAD الحالي؛ COMMENTED ومراجعة صاحب الحساب لا تُحتسب (INDEPENDENT_APPROVAL_MISSING)
- **MANUAL_ACCEPTANCE_REQUIRED**: المراجعات المطلوبة أو موافقة آخر دفع لم تُحسم لدى GitHub (REQUIRED_REVIEW_UNSATISFIED)
- **SECURITY_REVIEW_REQUIRED**: تحتاج الملاحظات أو الحدود الأمنية إلى حسم مستقل؛ رصد الكلمات ليس حكمًا بوجود ثغرة (SECURITY_EVIDENCE_REVIEW)
- **MANUAL_ACCEPTANCE_REQUIRED**: توجد معلومات ناقصة أو غير قابلة للتحقق؛ راجع UNKNOWN (UNKNOWN_EVIDENCE)

### الفحوص على HEAD الحالي

| الفحص | الحالة | الأدلة |
| --- | --- | --- |
| Windows Build | UNKNOWN | UNKNOWN |
| ↳ دليل غير مقبول | STALE_OR_OTHER_HEAD | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | UNKNOWN | UNKNOWN |
| ↳ دليل غير مقبول | STALE_OR_OTHER_HEAD | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | UNKNOWN | UNKNOWN |
| ↳ دليل غير مقبول | STALE_OR_OTHER_HEAD | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | UNKNOWN | UNKNOWN |
| ↳ دليل غير مقبول | STALE_OR_OTHER_HEAD | https://github.com/owner/project/actions/runs/200/job/4 |

### المراجعات والأمن والقبول اليدوي

- عدد الموافقات المطلوب من المستودع: 1
- الحد الأدنى المستقل وفق سياسة المدقق: 1
- الموافقون المستقلون على HEAD: لا يوجد
- قرار مراجعات GitHub: REVIEW_REQUIRED
- المراجعون المطلوبون: [] · الفرق: []
- Code scanning: KNOWN
- القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة
- مراجعة مسجلة: independent · COMMENTED · `0000000000000000000000000000000000000066` · https://github.com/owner/project/pull/102#pullrequestreview-1

### الأدلة الناقصة — UNKNOWN

- ci.Windows Build: NO_CURRENT_SUCCESS_EVIDENCE
- ci.Portable Rust: NO_CURRENT_SUCCESS_EVIDENCE
- ci.CodeQL: NO_CURRENT_SUCCESS_EVIDENCE
- ci.Gitleaks: NO_CURRENT_SUCCESS_EVIDENCE

## #104 — تعارض وفشل Windows وملاحظة أمنية

https://github.com/owner/project/pull/104

**التصنيفات:** MERGE_CONFLICT، CI_FAILED، SECURITY_REVIEW_REQUIRED، MANUAL_ACCEPTANCE_REQUIRED

- أولوية المراجعة: 2
- Draft: False · قابلية الدمج: False · GitHub: dirty
- HEAD: `0000000000000000000000000000000000000068` (feature-104)
- Base: main · SHA في PR: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- رأس الفرع الأساسي الحالي: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- التبعيات: CLEAR · الآباء: []

### العوائق

- **MERGE_CONFLICT**: يوجد تعارض مع الفرع الأساسي (BASE_CONFLICT)
- **CI_FAILED**: Windows Build: فشل على HEAD الحالي (CI_FAILED:Windows Build)
- **SECURITY_REVIEW_REQUIRED**: تحتاج الملاحظات أو الحدود الأمنية إلى حسم مستقل؛ رصد الكلمات ليس حكمًا بوجود ثغرة (SECURITY_EVIDENCE_REVIEW)
- **MANUAL_ACCEPTANCE_REQUIRED**: يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية (MANUAL_SCOPE_OR_EVIDENCE)
- **MANUAL_ACCEPTANCE_REQUIRED**: توجد معلومات ناقصة أو غير قابلة للتحقق؛ راجع UNKNOWN (UNKNOWN_EVIDENCE)

### الفحوص على HEAD الحالي

| الفحص | الحالة | الأدلة |
| --- | --- | --- |
| Windows Build | FAILED | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | https://github.com/owner/project/actions/runs/200/job/4 |

### المراجعات والأمن والقبول اليدوي

- عدد الموافقات المطلوب من المستودع: 1
- الحد الأدنى المستقل وفق سياسة المدقق: 1
- الموافقون المستقلون على HEAD: independent
- قرار مراجعات GitHub: APPROVED
- المراجعون المطلوبون: [] · الفرق: []
- Code scanning: KNOWN
- القبول اليدوي/الأجهزة: **UNKNOWN** — يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية
- مراجعة مسجلة: independent · APPROVED · `0000000000000000000000000000000000000068` · https://github.com/owner/project/pull/104#pullrequestreview-1

> إشارة أمنية تحتاج قراءة بشرية (COMMENT): Security review required: verify the trust boundary before merging.
> المصدر: https://github.com/owner/project/pull/104#issuecomment-1

### الأدلة الناقصة — UNKNOWN

- manual_acceptance: NOT_MEASURED_OR_SCOPE_UNCONFIRMED

## #101 — Independent reporting tool

https://github.com/owner/project/pull/101

**التصنيفات:** READY_FOR_FINAL_REVIEW

- أولوية المراجعة: 3
- Draft: False · قابلية الدمج: True · GitHub: clean
- HEAD: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (feature)
- Base: main · SHA في PR: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- رأس الفرع الأساسي الحالي: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- التبعيات: CLEAR · الآباء: []

### العوائق

لا توجد عوائق مكتشفة ضمن نطاق الأدلة المتاحة.

### الفحوص على HEAD الحالي

| الفحص | الحالة | الأدلة |
| --- | --- | --- |
| Windows Build | SUCCESS | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | https://github.com/owner/project/actions/runs/200/job/4 |

### المراجعات والأمن والقبول اليدوي

- عدد الموافقات المطلوب من المستودع: 1
- الحد الأدنى المستقل وفق سياسة المدقق: 1
- الموافقون المستقلون على HEAD: independent
- قرار مراجعات GitHub: APPROVED
- المراجعون المطلوبون: [] · الفرق: []
- Code scanning: KNOWN
- القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة
- مراجعة مسجلة: independent · APPROVED · `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` · https://github.com/owner/project/pull/101#pullrequestreview-1

## #103 — طلب تابع لفرع لم يدمج

https://github.com/owner/project/pull/103

**التصنيفات:** DEPENDENCY_BLOCKED

- أولوية المراجعة: 4
- Draft: False · قابلية الدمج: True · GitHub: clean
- HEAD: `0000000000000000000000000000000000000067` (feature-103)
- Base: feature-102 · SHA في PR: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- رأس الفرع الأساسي الحالي: `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- التبعيات: BLOCKED · الآباء: [102]

### العوائق

- **DEPENDENCY_BLOCKED**: يعتمد الطلب على فرع غير main؛ يلزم اعتماد الأساس ثم إعادة استهداف الطلب وفحصه (STACK_BASE_NOT_TARGET)
- عوائق الأساس #102: DRAFT، CI_PENDING، SECURITY_REVIEW_REQUIRED، MANUAL_ACCEPTANCE_REQUIRED

### الفحوص على HEAD الحالي

| الفحص | الحالة | الأدلة |
| --- | --- | --- |
| Windows Build | SUCCESS | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | https://github.com/owner/project/actions/runs/200/job/4 |

### المراجعات والأمن والقبول اليدوي

- عدد الموافقات المطلوب من المستودع: 1
- الحد الأدنى المستقل وفق سياسة المدقق: 1
- الموافقون المستقلون على HEAD: independent
- قرار مراجعات GitHub: APPROVED
- المراجعون المطلوبون: [] · الفرق: []
- Code scanning: KNOWN
- القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة
- مراجعة مسجلة: independent · APPROVED · `0000000000000000000000000000000000000067` · https://github.com/owner/project/pull/103#pullrequestreview-1

## حدود التقرير

- تقرير نقطة زمنية وليس تصريح دمج أو مراجعة للشيفرة
- موافقة مستقلة واحدة على الأقل سياسة للمدقق، حتى إذا كانت إعدادات المستودع تتطلب صفرًا
- رصد الكلمات الأمنية إشارة للمراجعة وقد يشمل ملاحظات تاريخية أو نفيًا لوجود ثغرة
- لا تُثبت فحوص Windows أو VM قبول الأجهزة الفعلية؛ لم تُشغّل اختبارات أجهزة
- تغير التعليقات أو قواعد الحماية أثناء الفحص قد لا يُكتشف؛ أعد الفحص قبل القرار النهائي

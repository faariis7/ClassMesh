# ClassMesh — ملخص تنفيذي لجاهزية طلبات الدمج

**FIXTURE_ONLY** · جمع الأدلة: **PARTIAL** · owner/project

الفترة: 2026-11-04T02:00:00Z — 2026-11-04T02:00:00Z. الهدف: main.

هذا دعم للقرار فقط؛ حتى READY_FOR_MERGE ليست إذن دمج. القرار النهائي لقائد التنسيق.

| المؤشر | عدد PRs |
| --- | ---: |
| الإجمالي | 6 |
| جاهزة للمراجعة المستقلة | 1 |
| جاهزة للمراجعة النهائية | 1 |
| مرشحة للدمج وفق الأدلة | 1 |
| محجوبة | 3 |
| فشل CI | 1 |
| عوائق أمان مؤكدة | 0 |
| لديها أدلة ناقصة | 3 |

الأعداد متداخلة. UNKNOWN في شرط إلزامي يمنع جاهزية الدمج.

## أهم خمسة إجراءات تالية

1. **#101 — COORDINATOR_MERGE_DECISION**: الشروط المسجلة القابلة للتحقق مستوفاة؛ أعد التحقق ثم اترك القرار لقائد التنسيق · المسؤول المقترح: **COORDINATION_LEAD** · يفتح 0 طلبات.
2. **#105 — REQUEST_INDEPENDENT_REVIEW**: اكتملت المتطلبات الآلية؛ يلزم مراجع مستقل مخول على HEAD الحالي · المسؤول المقترح: **INDEPENDENT_REVIEWER** · يفتح 0 طلبات.
3. **#106 — COMPLETE_FINAL_REVIEW**: استكمل العدد والشروط المسجلة للموافقات النهائية · المسؤول المقترح: **INDEPENDENT_REVIEWER** · يفتح 0 طلبات.
4. **#104 — FIX_FAILED_CI**: حلل سجل الوظيفة الفاشلة وأصلح السبب ثم اختبر HEAD الجديد · المسؤول المقترح: **BRANCH_DEVELOPER** · يفتح 0 طلبات.
5. **#102 — FINISH_DRAFT**: أكمل نطاق الطلب ثم اعرضه للمراجعة · المسؤول المقترح: **BRANCH_DEVELOPER** · يفتح 1 طلبات.

## ترتيب التبعيات

الأصل يسبق التابع في خطة المعالجة: `#101 → #105 → #106 → #104 → #102 → #103`

- `#102 → #103`

## #101 — Independent reporting tool

https://github.com/owner/project/pull/101

**الحالة: READY_FOR_MERGE** · التفاصيل: READY_FOR_MERGE

**الإجراء التالي: COORDINATOR_MERGE_DECISION** — الشروط المسجلة القابلة للتحقق مستوفاة؛ أعد التحقق ثم اترك القرار لقائد التنسيق

المسؤول المقترح: **COORDINATION_LEAD** · أولوية 1 (30 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 0 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 0؛ منها غير معروف: 0؛ الدرجات: dependents=+0، confirmed_security=+0، ci_failure=+0، tests_complete=+20، remaining_conditions=+10، multiple_dependencies=+0، missing_evidence=+0؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **CLEAR** · الطلبات الحاجبة: [] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **نعم**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` · Base: main `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **INTEGRATION_CURRENT** — ثبت checkout وآباء نسخة التكامل الحالية

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/4 |

**العوائق:**

لا توجد عوائق مسجلة ضمن نطاق الأدلة.

موافقات مستقلة: 1/1 · قرار GitHub: APPROVED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة

**أدلة المراجعات:**

- independent: APPROVED · https://github.com/owner/project/pull/101#pullrequestreview-1

## #105 — اجتاز الاختبارات ويحتاج مراجعًا مستقلًا

https://github.com/owner/project/pull/105

**الحالة: READY_FOR_INDEPENDENT_REVIEW** · التفاصيل: MANUAL_ACCEPTANCE_REQUIRED

**الإجراء التالي: REQUEST_INDEPENDENT_REVIEW** — اكتملت المتطلبات الآلية؛ يلزم مراجع مستقل مخول على HEAD الحالي

المسؤول المقترح: **INDEPENDENT_REVIEWER** · أولوية 2 (28 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 0 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 1؛ منها غير معروف: 0؛ الدرجات: dependents=+0، confirmed_security=+0، ci_failure=+0، tests_complete=+20، remaining_conditions=+8، multiple_dependencies=+0، missing_evidence=+0؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **CLEAR** · الطلبات الحاجبة: [] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **نعم**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` · Base: main `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **INTEGRATION_CURRENT** — ثبت checkout وآباء نسخة التكامل الحالية

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/4 |

**العوائق:**

- تنقص موافقة مستقلة على HEAD الحالي؛ COMMENTED ومراجعة صاحب الحساب لا تُحتسب (`INDEPENDENT_APPROVAL_MISSING`)

موافقات مستقلة: 0/1 · قرار GitHub: APPROVED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة

**الأدلة والإجراءات المتبقية:**

- independent_reviews: **REVIEW_REQUIRED** — APPROVED مستقلة وحديثة؛ COMMENTED وصاحب الحساب لا يُحتسبان

## #106 — موافقة مستقلة قائمة؛ يحتاج موافقة ثانية

https://github.com/owner/project/pull/106

**الحالة: READY_FOR_FINAL_REVIEW** · التفاصيل: MANUAL_ACCEPTANCE_REQUIRED

**الإجراء التالي: COMPLETE_FINAL_REVIEW** — استكمل العدد والشروط المسجلة للموافقات النهائية

المسؤول المقترح: **INDEPENDENT_REVIEWER** · أولوية 3 (28 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 0 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 1؛ منها غير معروف: 0؛ الدرجات: dependents=+0، confirmed_security=+0، ci_failure=+0، tests_complete=+20، remaining_conditions=+8، multiple_dependencies=+0، missing_evidence=+0؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **CLEAR** · الطلبات الحاجبة: [] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **نعم**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` · Base: main `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **INTEGRATION_CURRENT** — ثبت checkout وآباء نسخة التكامل الحالية

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | INTEGRATION_CURRENT | https://github.com/owner/project/actions/runs/200/job/4 |

**العوائق:**

- تنقص موافقة مستقلة على HEAD الحالي؛ COMMENTED ومراجعة صاحب الحساب لا تُحتسب (`INDEPENDENT_APPROVAL_MISSING`)

موافقات مستقلة: 1/2 · قرار GitHub: APPROVED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة

**أدلة المراجعات:**

- independent: APPROVED · https://github.com/owner/project/pull/101#pullrequestreview-1

**الأدلة والإجراءات المتبقية:**

- independent_reviews: **REVIEW_REQUIRED** — APPROVED مستقلة وحديثة؛ COMMENTED وصاحب الحساب لا يُحتسبان

## #104 — تعارض وفشل Windows وملاحظة أمنية

https://github.com/owner/project/pull/104

**الحالة: BLOCKED** · التفاصيل: BASE_REVALIDATION_REQUIRED، CI_FAILED، MANUAL_ACCEPTANCE_REQUIRED، MERGE_CONFLICT، SECURITY_REVIEW_REQUIRED

**الإجراء التالي: FIX_FAILED_CI** — حلل سجل الوظيفة الفاشلة وأصلح السبب ثم اختبر HEAD الجديد

المسؤول المقترح: **BRANCH_DEVELOPER** · أولوية 4 (3 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 0 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 6؛ منها غير معروف: 3؛ الدرجات: dependents=+0، confirmed_security=+0، ci_failure=+15، tests_complete=+0، remaining_conditions=+0، multiple_dependencies=+0، missing_evidence=-12؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **CLEAR** · الطلبات الحاجبة: [] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **نعم**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `0000000000000000000000000000000000000068` · Base: main `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | FAILED | UNKNOWN | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/200/job/4 |

**العوائق:**

- يوجد تعارض مع الفرع الأساسي (`BASE_CONFLICT`)
- Windows Build: فشل على HEAD الحالي (`CI_FAILED:Windows Build`)
- يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية (`MANUAL_SCOPE_OR_EVIDENCE`)
- لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس (`BASE_REVALIDATION_REQUIRED`)
- مراجعة أمنية مستقلة مطلوبة؛ نوع الدليل: REVIEW_REQUIRED (`SECURITY_EVIDENCE_REVIEW`)
- شروط ضرورية غير معروفة؛ لا يمكن إعلان جاهزية الدمج (`UNKNOWN_EVIDENCE`)

موافقات مستقلة: 1/1 · قرار GitHub: APPROVED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **UNKNOWN** — يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية

**الملاحظات الأمنية ومصادرها:**

- **REVIEW_REQUIRED**: إشارة نصية فقط؛ يلزم تقييم بشري، ولا تثبت ثغرة · https://github.com/owner/project/pull/104#issuecomment-1

**أدلة المراجعات:**

- independent: APPROVED · https://github.com/owner/project/pull/104#pullrequestreview-1

**الأدلة والإجراءات المتبقية:**

- ci: **UNSATISFIED** — كل فحص إلزامي مرتبط بـHEAD وتشغيله الحالي
- base: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس
- security: **REVIEW_REQUIRED** — الأمن: REVIEW_REQUIRED
- manual_acceptance: **UNKNOWN** — يلزم تحديد نطاق القبول اليدوي وتقديم أدلته؛ Windows CI وVM لا يثبتان اختبارات الأجهزة الفعلية
- merge_and_threads: **UNSATISFIED** — Draft والتعارض والخيوط المفتوحة تمنع التقدم
- evidence_completeness: **UNKNOWN** — يشمل قواعد الحماية وثبات جمع البيانات والصلاحيات
- manual_acceptance: **UNKNOWN** — NOT_MEASURED_OR_SCOPE_UNCONFIRMED
- base_validation: **UNKNOWN** — UNKNOWN

## #102 — مسودة مع نجاح CI على commit قديم فقط

https://github.com/owner/project/pull/102

**الحالة: BLOCKED** · التفاصيل: BASE_REVALIDATION_REQUIRED، CI_PENDING، DRAFT، MANUAL_ACCEPTANCE_REQUIRED، SECURITY_REVIEW_REQUIRED

**الإجراء التالي: FINISH_DRAFT** — أكمل نطاق الطلب ثم اعرضه للمراجعة

المسؤول المقترح: **BRANCH_DEVELOPER** · أولوية 5 (0 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 1 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 6؛ منها غير معروف: 3؛ الدرجات: dependents=+12، confirmed_security=+0، ci_failure=+0، tests_complete=+0، remaining_conditions=+0، multiple_dependencies=+0، missing_evidence=-12؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **CLEAR** · الطلبات الحاجبة: [] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **نعم**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `0000000000000000000000000000000000000066` · Base: main `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | UNKNOWN | UNKNOWN | UNKNOWN |
| Portable Rust | UNKNOWN | UNKNOWN | UNKNOWN |
| CodeQL | UNKNOWN | UNKNOWN | UNKNOWN |
| Gitleaks | UNKNOWN | UNKNOWN | UNKNOWN |

**العوائق:**

- الطلب مسودة ولم يُعرض للمراجعة النهائية (`DRAFT`)
- Windows Build: UNKNOWN (`CI_INCOMPLETE:Windows Build`)
- Portable Rust: UNKNOWN (`CI_INCOMPLETE:Portable Rust`)
- CodeQL: UNKNOWN (`CI_INCOMPLETE:CodeQL`)
- الفحص الأمني غير ناجح أو غير متاح: CodeQL (`SECURITY_CHECK:CodeQL`)
- Gitleaks: UNKNOWN (`CI_INCOMPLETE:Gitleaks`)
- الفحص الأمني غير ناجح أو غير متاح: Gitleaks (`SECURITY_CHECK:Gitleaks`)
- تنقص موافقة مستقلة على HEAD الحالي؛ COMMENTED ومراجعة صاحب الحساب لا تُحتسب (`INDEPENDENT_APPROVAL_MISSING`)
- المراجعات المطلوبة أو موافقة آخر دفع لم تُحسم لدى GitHub (`REQUIRED_REVIEW_UNSATISFIED`)
- لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس (`BASE_REVALIDATION_REQUIRED`)
- مراجعة أمنية مستقلة مطلوبة؛ نوع الدليل: REVIEW_REQUIRED (`SECURITY_EVIDENCE_REVIEW`)
- شروط ضرورية غير معروفة؛ لا يمكن إعلان جاهزية الدمج (`UNKNOWN_EVIDENCE`)

موافقات مستقلة: 0/1 · قرار GitHub: REVIEW_REQUIRED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة

**أدلة المراجعات:**

- independent: COMMENTED · https://github.com/owner/project/pull/102#pullrequestreview-1

**الأدلة والإجراءات المتبقية:**

- ci: **UNKNOWN** — كل فحص إلزامي مرتبط بـHEAD وتشغيله الحالي
- base: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس
- independent_reviews: **REVIEW_REQUIRED** — APPROVED مستقلة وحديثة؛ COMMENTED وصاحب الحساب لا يُحتسبان
- security: **REVIEW_REQUIRED** — الأمن: REVIEW_REQUIRED
- merge_and_threads: **UNSATISFIED** — Draft والتعارض والخيوط المفتوحة تمنع التقدم
- evidence_completeness: **UNKNOWN** — يشمل قواعد الحماية وثبات جمع البيانات والصلاحيات
- ci.Windows Build: **UNKNOWN** — NO_CURRENT_SUCCESS_EVIDENCE
- ci.Portable Rust: **UNKNOWN** — NO_CURRENT_SUCCESS_EVIDENCE
- ci.CodeQL: **UNKNOWN** — NO_CURRENT_SUCCESS_EVIDENCE
- ci.Gitleaks: **UNKNOWN** — NO_CURRENT_SUCCESS_EVIDENCE
- base_validation: **UNKNOWN** — UNKNOWN

## #103 — طلب تابع لفرع لم يدمج

https://github.com/owner/project/pull/103

**الحالة: BLOCKED** · التفاصيل: BASE_REVALIDATION_REQUIRED، DEPENDENCY_BLOCKED، MANUAL_ACCEPTANCE_REQUIRED

**الإجراء التالي: WAIT_FOR_DEPENDENCIES** — عالج الأصل أو الدورة أو الأب المجهول أولًا، ثم حدّث التابع وأعد فحصه

المسؤول المقترح: **COORDINATION_LEAD** · أولوية 6 (16 نقطة، NORMAL).

سبب الأولوية: يفتح معالجة 0 طلبات تابعة (مباشرة وغير مباشرة)؛ شروط متبقية: 3؛ منها غير معروف: 2؛ الدرجات: dependents=+0، confirmed_security=+0، ci_failure=+0، tests_complete=+20، remaining_conditions=+4، multiple_dependencies=+0، missing_evidence=-8؛ الأساس يسبق التابع؛ عدد الشروط تقدير حجم عمل نسبي وليس تقدير زمن

التبعيات: **BLOCKED** · الطلبات الحاجبة: [102] · آباء مجهولون: [].

يمكن البدء بالإجراء الحالي دون انتظار التبعيات: **لا**؛ لا يعني ذلك إمكانية دمج التابع.

HEAD: `0000000000000000000000000000000000000067` · Base: feature-102 `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

أدلة الأساس: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس

| الفحص | HEAD الحالي | نطاق التنفيذ | رابط الدليل |
| --- | --- | --- | --- |
| Windows Build | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/100/job/1 |
| Portable Rust | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/100/job/2 |
| CodeQL | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/200/job/3 |
| Gitleaks | SUCCESS | UNKNOWN | https://github.com/owner/project/actions/runs/200/job/4 |

**العوائق:**

- لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس (`BASE_REVALIDATION_REQUIRED`)
- يلزم معالجة الآباء ثم تحديث التابع وإعادة فحصه؛ BLOCKED (`DEPENDENCIES_BLOCKED`)
- شروط ضرورية غير معروفة؛ لا يمكن إعلان جاهزية الدمج (`UNKNOWN_EVIDENCE`)

موافقات مستقلة: 1/1 · قرار GitHub: APPROVED · خيوط مفتوحة: 0.

القبول اليدوي/الأجهزة: **NOT_APPLICABLE** — التغيير محصور في الأداة أو التوثيق؛ لا يدعي التقرير تأهيل الأجهزة

**أدلة المراجعات:**

- independent: APPROVED · https://github.com/owner/project/pull/103#pullrequestreview-1

**الأدلة والإجراءات المتبقية:**

- base: **UNKNOWN** — لا يوجد دليل تنفيذ كافٍ لربط الفحوص بالأساس
- dependencies: **UNSATISFIED** — الأصل قبل التابع
- evidence_completeness: **UNKNOWN** — يشمل قواعد الحماية وثبات جمع البيانات والصلاحيات
- base_validation: **UNKNOWN** — UNKNOWN

## مقارنة V1 وV2 على Snapshot واحدة

SHA256: `c91eab5fd986ed5617279c479884aff8de58025e7ba7ff4d638bfc18c9a66298`

| PR | تصنيفات V1 | مرحلة V2 | الإجراء |
| --- | --- | --- | --- |
| #101 | READY_FOR_FINAL_REVIEW | READY_FOR_MERGE | COORDINATOR_MERGE_DECISION |
| #102 | DRAFT, CI_PENDING, SECURITY_REVIEW_REQUIRED, MANUAL_ACCEPTANCE_REQUIRED | BLOCKED | FINISH_DRAFT |
| #103 | DEPENDENCY_BLOCKED | BLOCKED | WAIT_FOR_DEPENDENCIES |
| #104 | MERGE_CONFLICT, CI_FAILED, SECURITY_REVIEW_REQUIRED, MANUAL_ACCEPTANCE_REQUIRED | BLOCKED | FIX_FAILED_CI |
| #105 | MANUAL_ACCEPTANCE_REQUIRED | READY_FOR_INDEPENDENT_REVIEW | REQUEST_INDEPENDENT_REVIEW |
| #106 | MANUAL_ACCEPTANCE_REQUIRED | READY_FOR_FINAL_REVIEW | COMPLETE_FINAL_REVIEW |

## حدود الإثبات

- تقرير نقطة زمنية لدعم القرار؛ READY_FOR_MERGE لا يمنح إذن الدمج، والقرار لقائد التنسيق
- موافقة مستقلة واحدة على الأقل على HEAD الحالي؛ لا تُحتسب موافقة صاحب PR أو الحساب المستخدم أو مالك المستودع
- سجلات checkout وآباء commit أدلة تنفيذ GitHub؛ ليست تصديقًا تشفيريًا أو إثبات كفاية الاختبارات، ويمكن لمؤلف Workflow التأثير في السجلات
- HEAD_ONLY يثبت checkout لرأس الفرع فقط؛ لا يدعي اختبار دمجه مع أحدث أساس
- الاختبارات وWindows CI وVM لا تثبت قبول الأجهزة الفعلية؛ الأدلة المادية وقواعد الحماية غير المدعومة تبقى UNKNOWN
- الملاحظة التاريخية لم تُثبت محلولة؛ RESOLVED يصف حالة GitHub المسجلة فقط
- المالكون المقترحون أدوار لا تكليفات فعلية؛ حجم العمل تقدير بعدد الشروط وليس بساعات
- تغير التعليقات والمراجعات والسياسات أثناء الجمع قد لا يُكتشف؛ أعد الفحص قبل القرار النهائي

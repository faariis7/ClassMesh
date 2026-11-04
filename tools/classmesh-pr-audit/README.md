# ClassMesh PR Readiness Auditor V2.1

أداة مستقلة للقراءة فقط تساعد قائد التنسيق على معرفة: ما الجاهز، وما العائق، وما الإجراء التالي، ومن الدور المسؤول، وأي أصل يفتح أكبر عدد من الطلبات. تطوّر تنفيذ V1 نفسه ولا تغيّر تطبيقات ClassMesh أو المجدولات أو الأجهزة.

## التشغيل

المتطلبات: Python 3.11+ وGitHub CLI حديث مصادق مسبقًا على `github.com`، وmacOS أو Linux للكتابة الآمنة عبر directory file descriptors. لا تحتاج الاختبارات أو المثال إلى شبكة أو gh. عند عدم دعم gh لخيار قراءة السجلات، تظهر أدلة الأساس UNKNOWN بدل نجاح مفترض.

```sh
python3 tools/classmesh-pr-audit/audit.py \
  --repo faariis7/ClassMesh \
  --compare-v1 --save-snapshot \
  --output-dir /tmp/classmesh-pr-report-v2
```

افتراضيًا يُكتب `report.json` و`report.md` فقط. `--save-snapshot` يضيف `snapshot.json` داخل المجلد نفسه، و`--compare-v1` يضيف المقارنة إلى التقريرين. يجب أن يكون المجلد الأب موجودًا. لا كاش أو bytecode أو ملفات بناء. لا تُحفظ سجلات CI الخام؛ تُقرأ في الذاكرة لاستخراج SHA ثم تُهمل.

الكتابة محصورة في مجلد مثبت بـdescriptor. تُرفض symlinks للمجلد نفسه وملفات المخرجات، وhardlinks والملفات الخاصة. `/tmp` الأب المعتاد في macOS مقبول. يُجهّز المحتوى قبل الاستبدال الذري لكل ملف؛ الملفات ليست معاملة ذرية مشتركة، لذا قارن التوقيت بعد انقطاع الكتابة. التقارير والـsnapshot قد تتضمن تعليقات خاصة؛ المثال الملتزم في Git اصطناعي فقط.

كل REST طلب `GET`، و`POST /graphql` يرسل query ثابتة فقط. تُرفض mutations/subscriptions. لا push أو merge أو review أو comment أو workflow dispatch أو تعديل صلاحيات داخل المدقق. فتح PRs لتسليم تطوير الأداة عملية منفصلة عن الفحص.

لا تطبع الأداة tokens أو stderr أو السجلات الخام. تزيل `GH_DEBUG`، وتحجب أنماط GitHub credentials والقيم المعروفة في متغيرات GH_TOKEN/GITHUB_TOKEN ونظائر Enterprise قبل التحليل والحفظ. لا تنفذ تسجيل الدخول.

| Exit | المعنى |
| --- | --- |
| 0 | جمع مكتمل ضمن نطاق السياسة، وقد تبقى عوائق معروفة؛ لا يعني جاهزية الدمج. |
| 2 | تقرير صالح PARTIAL؛ توجد UNKNOWN أو تغير أثناء الجمع أو صلاحيات/أدلة ناقصة. |
| 3 | مدخلات أو كتابة فاشلة؛ لا تعتمد على تقرير قديم متروك. |

الحدود: `--timeout 20` ثانية لكل طلب (1–60)، `--deadline 600` للجمع (1–3600)، `--max-requests 1200` (1–5000)، و30 صفحة ×100 لكل اتصال. لا retries أو sleeps أو polling. عند rate limit يتوقف النقل اللاحق ويصدر تقرير جزئي. تُلتقط استجابة gh في الذاكرة قبل رفض الحجم الذي يتجاوز 8 MiB؛ المدخل fixture محدود بـ10 MiB. اقتطاع الصفحات أو خيط يتجاوز 100 تعليق يبقى UNKNOWN.

## المراحل وشروط القرار

`readiness_stage` هي المرحلة الأساسية؛ `classifications` و`blockers` يحتفظان بجميع الأسباب التفصيلية. `merge_authorized` دائمًا false.

| المرحلة | الدلالة |
| --- | --- |
| READY_FOR_INDEPENDENT_REVIEW | اكتملت البوابات الآلية والأدلة المطلوبة؛ تنقص المراجعة المستقلة. |
| READY_FOR_FINAL_REVIEW | توجد موافقة مستقلة والأدلة الأساسية مكتملة، وتبقى متطلبات مراجعة نهائية/أمنية مسجلة. |
| READY_FOR_MERGE | جميع الشروط المسجلة القابلة للتحقق مستوفاة؛ مرشح لقرار القائد، وليس تصريحًا. |
| BLOCKED | عائق معروف مثل CI فاشل/جارٍ أو تعارض أو Draft أو خيوط/طلبات تغييرات أو تبعية أو تكامل قديم. |
| UNKNOWN | بيانات ضرورية غير متاحة أو غير موثوقة؛ لا تُخمن النتيجة. |

وجود عائق معروف مع أدلة مجهولة يُظهر BLOCKED **ويحتفظ** بالمجهولات. التصنيفات التفصيلية تشمل CI_FAILED وCI_PENDING وSECURITY_REVIEW_REQUIRED وDEPENDENCY_BLOCKED وMERGE_CONFLICT وMANUAL_ACCEPTANCE_REQUIRED وDRAFT، ويضاف BASE_REVALIDATION_REQUIRED. `technical_blockers` يفصل مشاكل التنفيذ عن نقص المراجع وحده. `conditions` يوضح حالة كل شرط إلزامي؛ UNKNOWN يمنع READY_FOR_MERGE.

الحد الأدنى المحلي موافقة مستقلة واحدة، ولو طلبت إعدادات المستودع صفرًا. يجب أن تكون APPROVED على HEAD الحالي من User له write/maintain/admin؛ تُستبعد موافقة المؤلف والحساب المستخدم ومالك المستودع والبوتات. COMMENTED ليست موافقة. رأي APPROVED لا يُمحى بتعليق لاحق، لكنه يتغير بـCHANGES_REQUESTED أو DISMISSED لاحقين. صلاحية مجهولة لا تُحتسب. تُقرأ الحماية التقليدية وRulesets، وتبقى قواعد غير مدعومة كالنشر الإلزامي أو merge queue غير محسومة. لا يُتجاوز CODEOWNERS أو موافقة آخر push أو قرار GitHub.

القبول اليدوي/المادي NOT_APPLICABLE فقط لنطاق الأداة/التوثيق الذي يمكن إثباته. التغييرات الأخرى تحتاج تحديد انطباق القبول وأدلته ويظل UNKNOWN؛ هذا ليس أمرًا بتشغيل أجهزة لكل تعديل. Windows CI أو VM أو نص يدعي النجاح لا يثبت GPU أو Session 0 أو جهازين فعليين.

## HEAD والأساس ونسخة التنفيذ

1. يُربط كل فحص بـHEAD الحالي وتطبيق github-actions، وأحدث تشغيل pull_request لنفس PR ومسار Workflow وcheck suite ومحاولة التشغيل. النجاح القديم أو محاولة سابقة أو اسم مشابه لا يُحتسب. skipped/neutral ليسا نجاحًا للبوابات الأساسية.
2. HEAD SHA في Workflow وحده لا يثبت اختبار التكامل. يجلب المدقق بيانات job المرتبط بالفحص، ويتحقق من run_id/run_attempt/head_sha/status/conclusion، ثم يستخرج SHA من `git log -1 --format=%H` داخل checkout واحد غير ملتبس.
3. تُقرأ بيانات commit الثابتة وآباؤه من GitHub. `[base, HEAD]` يثبت نسخة التكامل المحددة: INTEGRATION_CURRENT أو INTEGRATION_STALE بحسب رأس الأساس الحالي. نتيجة HEAD الأصلية تبقى ظاهرة حتى حين يتطلب التكامل إعادة تحقق.
4. checkout لـHEAD نفسه يظهر HEAD_ONLY، ولا يُلغى لمجرد تحرك main عندما تكون قاعدة strict غير مطلوبة. هذا **لا يثبت** تكاملًا مع main. strict=true أو سياسة مجهولة تحتاج دليل تكامل.
5. إعادة تشغيل Workflow تحتفظ بالـSHA/ref الأصليين؛ run_attempt أو وقت أحدث وحده لا ينعش دليل الأساس. يجب رصد نسخة فعلية وآباء صحيحين. غياب السجل/صلاحياته أو تعدد checkouts أو تغيير شجرة ظاهر بعدها يترك UNKNOWN وBASE_REVALIDATION_REQUIRED.
6. تُعاد قراءة PR والأساس والجرد والمراجعات والخيوط والتعليقات. تُفصل عضوية الجرد عن تغيّر أدلة كل PR؛ تغيّر HEAD/base/merge SHA يمنع اعتماد دليل الأساس، وتغيّر مراجعة أو تعليق يمنع جاهزية الطلب دون إلغاء دليل checkout صحيح. الجمع ليس معاملة GitHub ذرية؛ أعد الفحص قبل القرار النهائي.

هذه **أدلة تنفيذ Workflow** وليست تصديقًا تشفيريًا لكفاية الاختبارات: المؤلف يستطيع التأثير في السجل أو السكربت، والاختبار قد يغيّر ملفات بطرق لا يرصدها parser. لا يستبدل ذلك مراجعة Workflow والشيفرة. check أو status خارجي بلا ربط موثوق يبقى UNKNOWN. قاعدة حماية جديدة أو سياق إضافي يُقيّم بالاسم وapp ID الدقيقين؛ legacy status وحده لا يثبت مصدره.

## الأمن والإجراءات والأولوية

| حالة الملاحظة | الدليل |
| --- | --- |
| CONFIRMED_BLOCKER | تنبيه GitHub مفتوح مرتبط بالنسخة الحالية، أو CHANGES_REQUESTED مستقل أمني على HEAD؛ يؤكد عائقًا مسجلًا، لا قابلية الاستغلال. |
| REVIEW_REQUIRED | إشارة نصية أو خيط مفتوح أو حدود حساسة تحتاج حكمًا بشريًا. |
| HISTORICAL_NOTE | تاريخ الملاحظة يسبق تاريخ HEAD المسجل؛ لا يعني أنها حُلّت. |
| RESOLVED | حالة حسم مسجلة لدى GitHub أو رأي أحدث يرفع طلب التغييرات؛ النص وحده لا يكفي. |
| UNKNOWN | المصدر أو الرابط أو ربط النسخة أو صلاحية الوصول ناقصة. |

لكل ملاحظة مصدر ورابط وسبب. الكلمات وحدها ليست ثغرة، وعبارة resolved لا تغلق خيطًا مفتوحًا ولو كانت أسطره قديمة. لا يقرأ المدقق محتوى أسرار secret-scanning؛ يجمع Gitleaks وcode-scanning ويترك نقص الصلاحية ظاهرًا.

لكل PR: `next_action` رمز ثابت، `action_reason` عربي، `suggested_owner` دور (BRANCH_DEVELOPER / INDEPENDENT_REVIEWER / COORDINATION_LEAD / UNASSIGNED)، و`priority` بها rank/score/level/factors/reasons، و`blocking_prs` و`required_evidence` و`can_proceed_without_dependencies`. هذا الأخير يخص **بدء الإجراء** كإصلاح CI، وليس السماح بدمج التابع. لا تُخترع أسماء أشخاص أو تكليفات من نص تعليق.

تُكتشف التبعيات من هوية مستودع/فرع Base، أو سطر صريح مثل `Depends-On: #650, #652`؛ الإشارات العادية ليست تبعيات. الدمج المثبت إلى الفرع المستهدف يرفع تبعية صريحة؛ الإغلاق دون دمج أو الوصول المفقود لا يرفعها. حد 32 مرجعًا مصرحًا لكل PR؛ تجاوزه ظاهر. الفرع غير المستهدف يبقى معطلًا حتى يُعتمد الأصل ويُحدث/يُعاد استهداف التابع. الدورات والآباء الملتبسون ظاهرون، والسلاسل لا تختلق حواف بين آباء متوازيين.

الأصل يسبق التابع في الترتيب؛ عند تساوي أهلية الترتيب تُحسب النقاط: +12 لكل تابع فريد مباشر/غير مباشر، +50 لعائق أمني مؤكد، +15 لفشل CI، +20 لاكتمال الفحوص، حتى +10 لقلة الشروط المتبقية، −3 لكل تبعية إضافية، −4 لكل شرط UNKNOWN. الأرقام سياسة ترتيب قابلة للتفسير وليست SLA أو تقدير ساعات. لا وزن لكلمة Security أو ملاحظة تاريخية وحدها. يعرض التقرير أهم خمسة إجراءات وأسباب الترتيب.

## Schema والتوافق

إصدار **report.schema_version=2**. مدخل Snapshot ما زال schema_version=1 مع حقول اختيارية جديدة؛ الـsnapshot القديم يقرأ بأمان، لكن دليل أساسه المفقود UNKNOWN. `policy.analyze` يحفظ سياسة V1 للمقارنة، وCLI يستخدم `analyze_v2`.

أضيفت readiness_stage/merge_authorized/conditions/technical_blockers/base_validation وحقول الإجراءات المذكورة، وتصنيفات الملاحظات وأسبابها، وdependency_cycles/dependency_order_unresolved، وإحصاءات المراحل وtop_actions. حقول الهوية وci/reviews/branch_policy/manual_acceptance والمخرجات الأساسية محفوظة. تغير معنى summary.all_ready إلى استيفاء شروط V2؛ لا يعتمد المستهلك على تصنيف READY_FOR_FINAL_REVIEW القديم كإذن دمج. `suggested_review_priority` محفوظ بجانب priority.rank. يجب أن يتحقق المستهلك من schema_version.

`--compare-v1` يقيّم **نفس المدخل في الذاكرة** بالمحركين، مع SHA256 لـJSON canonical (sort_keys، UTF-8، separators بلا مسافات). لا يجمع Snapshot ثانية للمقارنة. تنظيف credentials يسبق الحفظ والحساب، لذا يمكن إعادة إنتاج المقارنة من snapshot.json المحفوظة.

## الاختبارات والمثال وCI

```sh
python3 -B -m unittest discover -s tools/classmesh-pr-audit/tests -v
python3 -B tools/classmesh-pr-audit/verify.py
python3 tools/classmesh-pr-audit/audit.py \
  --fixture tools/classmesh-pr-audit/examples/input.json --compare-v1 \
  --output-dir /tmp/classmesh-pr-example-v2
```

المثال exit=2 عمدًا ويغطي 6 طلبات: مرشحًا للدمج، Draft مع CI قديم، تابعًا، تعارضًا/CI فاشلًا، مراجعة مستقلة فقط، وموافقة نهائية إضافية. [التقرير العربي](examples/report.md) و[JSON](examples/report.json) قابلان لإعادة الإنتاج حرفيًا. verify.py يتحقق من syntax دون bytecode، ومن المخرجين، ومع `--scope-base SHA --scope-head SHA` يفحص Git diff للأداة أو ملف Workflow المخصص فقط. لا اتصالات شبكية أثناء الاختبارات.

حُفظت الاختبارات الـ61 الأصلية؛ التفاصيل الجديدة ونتائج TDD في [V2_PLAN.md](V2_PLAN.md). Workflow المستقل يُسلّم في PR ثانٍ مبني على #685، ويضيف فقط `.github/workflows/classmesh-pr-audit.yml`: Python 3.11 و3.14، unittest وsyntax والمثال والنطاق وwhitespace على GitHub-hosted Linux، contents:read وبدون token خاص أو cache أو أجهزة. لا يعدل CI الرئيسي أو Windows. تُختبر شيفرة الأب نفسها الموروثة في طلب Workflow؛ الدمج اليدوي للأب ثم إعادة استهداف التابع من مسؤولية القائد.

الملفات: github_source.py للنقل، policy.py لسياسة V1 والتحقق الحالي من CI/الموافقات، execution_evidence.py لأدلة الأساس، security_notes.py لتصنيف الأمن، dependencies.py للرسم والأولوية، decisions.py للمراحل والإجراءات، reporting.py للتقرير، audit.py للواجهة والكتابة، verify.py للتحقق المحلي/CI.

مراجع العقود: [Workflow reruns](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)، [pull_request checkout](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)، [Workflow runs](https://docs.github.com/en/rest/actions/workflow-runs)، [Workflow jobs](https://docs.github.com/en/rest/actions/workflow-jobs)، [Branch rules](https://docs.github.com/en/rest/repos/rules).

## V2.1: الثبات والأداء وتشخيص PARTIAL

`PARTIAL` لا يعني بالضرورة فشل الجرد. افحص `collection_diagnostics.inventory` لمعرفة حالة القراءتين، والأرقام المضافة/المزالة، وسبب API الأصلي. افحص `pull_requests[].stability` للتغيّرات المحلية. التفاصيل والقياسات ونتائج TDD في [V2_1_VALIDATION.md](V2_1_VALIDATION.md).

| التشخيص | الأثر |
| --- | --- |
| INVENTORY_MEMBERSHIP_CHANGED | تغيرت قائمة الطلبات؛ الجرد والتبعيات يحتاجان إعادة جمع. |
| INVENTORY_UNAVAILABLE | إحدى القراءتين ناقصة؛ يُحفظ TIMEOUT/FORBIDDEN/RATE_LIMITED أو سبب الميزانية. |
| REFS_CHANGED / BASE_BRANCH_CHANGED | تغيّر HEAD أو أساس أو نسخة دمج؛ يمنع جاهزية الطلب المعني ودليل الأساس. |
| REFS_UNAVAILABLE / BASE_BRANCH_UNAVAILABLE | تعذر إثبات ثبات المراجع؛ UNKNOWN. |
| REVIEWS_CHANGED / REVIEW_DATA_UNAVAILABLE | تغيّر اعتماد/قرار/خيط أو نقص مصدره؛ لا تعاد الاستفادة من موافقة سابقة. |
| DISCUSSION_CHANGED / METADATA_CHANGED | تغيّر تعليق أو بيانات مؤثرة مثل body أو Draft؛ مراجعة جديدة مطلوبة. |
| LATE_PR_CHANGE | تغير ظهر في الجرد الأخير بعد إغلاق قراءة الطلب؛ يبقى غير محسوم محليًا. |
| EXECUTION_BUDGET_RESERVED | حُفظت ميزانية للإغلاق؛ دليل الوظيفة الذي لم يُجمع UNKNOWN. |

تعديل عنوان أو وقت تحديث فقط لا يبطل الجرد إذا بقيت البيانات المؤثرة وقراءتا المراجعات متطابقتين. ترتيب IDs وحده ليس تغيرًا. لا يختفي تغيّر العدد أو HEAD أو سحب موافقة تحت هذا الاستثناء.

يجمع المدقق الأدلة المنظمة أولًا، ثم يقرأ الوظائف وسجلاتها، ثم يعيد التحقق. تُجمع بيانات jobs لكل run/attempt مرة واحدة داخل التشغيل، وتبقى قراءة كل log وربطه بالـHEAD والمحاولة إلزامية. لا تستخدم بيانات تشغيل سابق. يُحجز أثناء قراءة السجلات جزء محدود من الطلبات والوقت للإغلاق؛ الحجز تقدير ولا يضمن اكتمال مصادر ضخمة متعددة الصفحات.

`collection_metrics` يعرض الاستدعاءات الفعلية، الزمن، الأخطاء والمحاولات التي لم تُرسل بحسب الفئة. هذه حقول اختيارية مضافة إلى schema 2؛ المخرجات القديمة والمثال الحالي محفوظة. تظل `merge_authorized=false`، وتغيرات القواعد/الصلاحيات أو CI بعد قراءتها قد لا تُلتقط في هذه الملاحظات المتتابعة.

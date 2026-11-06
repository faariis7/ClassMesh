# Windows MVP — حزمة تجربة موحدة

تحتوي `classmesh-windows-mvp-x64.zip` على Teacher UI وService وWorker من
نفس checkout ونفس تشغيل ومحاولة وjob في GitHub Actions. ليست إصدار إنتاج
معتمدًا: لا تمنح حزمة SHA256 سلطة توقيع أو اعتماد جهاز، ولا توفر مثبت Service.
ترتبط هذه الخطوة بـMVP #688. طلبات #689 و#694 و#691 مستقلة ولم تُضمّن هنا.

## التنزيل والتحقق

نزّل artifact المسمى `classmesh-windows-mvp-x64` من **Windows Build الناجح**
لطلب الدمج المطلوب. داخله ZIP واحد وملف SHA256. خذ رقم التشغيل ومحاولته
وبصمتي `mvp_zip_sha256` و`mvp_index_sha256` من سجل خطوة التغليف الموثوق.
يستخدم المشغّل بصمة الفهرس المستقلة للتحقق من الملفات داخل المجلد المستخرج.

في حدث PR، يستخدم CI الـmerge commit الاختباري الذي تختاره `actions/checkout`
افتراضيًا؛ `source_revision` في `mvp-bundle-index.json` هو **ذلك commit الفعلي**،
وليس افتراضًا بأنه HEAD فرع PR. جميع البرامج الثلاثة تحمل إيصالات البناء نفسها.
لا تخلط هذه الحزمة مع ملفات من artifact آخر أو محاولة CI أخرى.

استخدم PowerShell عاديًا غير مرتفع، واستخرج الحزمة في مجلد TEMP خاص جديد
على قرص محلي بمسار خالٍ من الروابط وjunctions. تحقق من ZIP قبل تشغيل سكربتاته.

```powershell
$zip = 'C:\path\classmesh-windows-mvp-x64.zip'
$expectedZipSha256 = '<64 hex from the trusted CI run>'
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ine $expectedZipSha256) {
    throw 'ZIP SHA256 mismatch'
}
$bundle = Join-Path $env:TEMP ('ClassMesh-MVP-package-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $bundle) { throw 'Destination already exists' }
Expand-Archive -LiteralPath $zip -DestinationPath $bundle
$source = '<40 lowercase hex actual CI checkout SHA>'
$run = '<CI run ID>'
$attempt = '1' # استخدم المحاولة الفعلية، لا تفترض 1 في إعادة التشغيل
$ci = @{
    ExpectedSourceRevision = $source
    ExpectedCiRunId = $run
    ExpectedCiRunAttempt = $attempt
    ExpectedIndexSha256 = '<mvp_index_sha256 from the trusted CI log>'
}
& "$bundle\windows-mvp-launch.ps1" -Mode Validate -BundleDir $bundle @ci
```

إذا كانت سياسة جهاز المختبر تمنع scripts محلية غير موقّعة، استخدم قناة تنفيذ
وافق عليها مسؤول المختبر. اختبار VM يستخدم `powershell.exe -NoProfile
-ExecutionPolicy RemoteSigned -File ...` للعملية المؤقتة فقط، بعد التحقق من
بصمة التنزيل. لا يستدعي المشغّل `Set-ExecutionPolicy` ولا يغيّر سياسة مستخدم أو
جهاز أو Group Policy. السياسة المؤسسية الأعلى تظل نافذة؛ ليست هذه موافقة
على تجاوزها. لا تستخدم `Unblock-File` على تنزيل غير متحقق منه.

## التشخيص وتشغيل Teacher

```powershell
& "$bundle\windows-mvp-launch.ps1" -Mode Diagnose -BundleDir $bundle @ci
& "$bundle\windows-mvp-launch.ps1" -Mode Smoke -BundleDir $bundle @ci
# Launch يترك نافذة Teacher الناجحة مفتوحة بطلب صريح، وSmoke يغلق عمليته.
& "$bundle\windows-mvp-launch.ps1" -Mode Launch -BundleDir $bundle @ci
```

يُطبع مسار `mvp-report.json` داخل TEMP جديد باسم `ClassMesh-MVP-<guid>`.
يمكن تحديد `-ReportDir` بهذا النمط كابن مباشر جديد لـTEMP. إعادة استخدامه مرفوضة؛
لا يُستبدل تقرير قديم بتقرير نجاح مضلل. التقرير يتضمن:

- التحقق من جميع الملفات، PE x64، مصدر البرامج وإيصالات CI، ومتطلبات VC++.
- حالة SCM الفعلية لـ`ClassMeshService`، حسابها، PID/session وتطابق برنامجها.
- وجود ملفات الهوية والتفويض والتهيئة، وأخطاء الوصول أو schema؛ بيانات الهوية
  المقروءة **غير معتمدة**. لا يفتح المشغّل مفتاح CNG ولا يثبت trust أو ACL.
- عمليات Worker الفعلية، الجلسة وparent PID وزمن الإنشاء والبصمة وربط وسيط pipe.
  وجود عملية أو اسم pipe ليس نجاح IPC مصادق عليه.
- نتيجة نافذة Teacher المستجيبة في جلسة المستخدم العادية، وقرار التنظيف.
- عوائق واضحة؛ `integrated_test_passed=false` و`merge_authorized=false` دائمًا.

رموز الخروج: **0** للتحقق من سلامة الحزمة فقط؛ **1** فشل تحقق أو تشغيل؛ **2**
تشخيص/تشغيل جزئي مع بقاء أدلة التكامل محجوبة أو غير مثبتة. نجاح نافذة Teacher
مع رمز 2 لا يعني نجاح Teacher→Service→Worker أو تفويض المستخدم.

لا يُنشئ المشغّل Service ولا يبدأها أو يوقفها، ولا يكتب ProgramData أو Registry
أو CNG أو ACL، ولا يبدأ Worker يدويًا. FileTransfer وClipboard لا يُفعّلان.
Service غير المسجلة تظهر `SERVICE_NOT_REGISTERED`. الملفات الغائبة تظهر
`ENROLLMENT_MISSING`، وفشل CIM/قراءة الملف يبقى UNKNOWN مع سبب الفشل.

## ما يحتاجه مطور Service

يلزم مسار تثبيت محمي ومراجع للهوية والتفويض وcontrol-runtime، وسلطة شهادات
مقبولة ومفتاح CNG يمكن لـLocalSystem استخدامه، ثم Service مسجلة ومصرح بها
وتشغيل Worker في الجلسة الصحيحة. تظل مراجعة Teacher authorization في #694
مستقلة. لا تنسخ ملفات TEMP إلى ProgramData كحل التفافي. بعد ذلك يلزم اختبار
مستقل لتبادل IPC المصادق عليه وTeacher QUIC وإظهار إطارات حقيقية؛ هذا المشغّل
الراصد لا يحتل pipe العامل أو يحاكي رسائله. مع عدم توفر Service مصرح بها، يبقى
هذا اختبار حزمة ونافذة وتشخيص فقط؛ M1/M2/M3 و#288/#411 لا تُغلق تلقائيًا.

حدود المراجعة الأمنية: تعاملت المراجعة الذاتية مع ملفات ZIP/JSON والبصمات
وبيانات CIM والهوية بوصفها مدخلات غير موثوقة. لا يختار JSON مسارات تنفيذ حرة،
ولا تمنح بيانات الحضور تفويضًا. اختبارات الرفض والتنظيف مرفقة، وتظل المراجعة
الأمنية المستقلة مطلوبة قبل قرار الدمج؛ لا تُستبدل بنجاح CodeQL أو هذا التشخيص.

## البناء والتوقيع والتنظيف

CI يسجل بصمة كل exe فور نجاح `cargo build`، مع SHA checkout ورقم التشغيل
والمحاولة واسم job. قبل Stage يقارن السياق والبصمات ويرفض فقد إيصال أو تغيّر
ملف أو وجود مجلد خرج سابق. يستخدم `IndexBundle/ValidateBundle/PreflightRuntime`
الحالية للـTeacher والـService/Worker ثم يختبر ZIP بعد فكّه. لا تُنزّل exes من
تشغيل سابق. schema الحزمة الموحدة 1 ولا يغيّر schemas الفهارس القديمة.

`phase13-release-manifest.ps1` موجود كما هو للتحقق الاختياري المستقل، دون تغيير
آلية التوقيع القائمة. لا توجد هوية أو CA أو سر أو توقيع إنتاجي داخل هذه الحزمة.
البصمات تكشف التلف والتبديل بالنسبة إلى مصدر التنزيل الموثوق؛ ليست بديلًا
عن توقيع موثوق أو مثبت محمي. يحتفظ المشغّل بملفات الحزمة مفتوحة للقراءة مع منع
مشاركة الكتابة والحذف خلال التحقق والتشغيل على Windows؛ ليس loader إنتاجيًا.

Smoke ينهي فقط process object الذي أنشأه في ذلك التشغيل، حتى عند فشل النافذة.
Launch يبقي النافذة الناجحة فقط؛ أغلقها يدويًا. احذف فقط مجلد الاستخراج ومجلد
التقرير اللذين أنشأتهما للتجربة بعد حفظ الأدلة. لا تحذف ProgramData أو مفاتيح أو
عمليات أو خدمات سابقة. لا يغيّر المشغّل موارد تسجيل الجهاز.

## الاختبارات

```powershell
.\scripts\tests\windows_mvp_bundle.ps1
.\scripts\tests\windows_mvp_diagnostics.ps1
```

الـfixtures تولد PE صغيرًا للتحقق فقط ولا تشغله. اختبار VM منفصل يستخدم ملفات
CI الحقيقية. RED موثق قبل التنفيذ: اختبارات مصدر/سلامة الحزمة 13 فشل؛ التشخيص
7 فشل؛ المشغّل/الملفات 6 فشل؛ ربط جلسة Worker/صلاحية Teacher 9 فشل. النتائج
الفعلية وأرقام تشغيل CI وSHA وبصمة ZIP وأدلة VM تُرفق بتسليم PR، ولا تُستنتج
من نتائج fixtures. يُمنع ادعاء SCM/IPC أو اختبار أجهزة فعلية من هذه الاختبارات.

مراجع السلوك: [GitHub PR checkout](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)،
[PowerShell process execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies).

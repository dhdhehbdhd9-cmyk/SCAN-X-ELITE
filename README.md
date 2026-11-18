# SCAN-X ELITE — Phase 3 (Hardened)

أداة لاكتشاف الأسرار داخل المستودعات على Linux وAndroid Termux، محليًا أو عبر رابط GitHub عام. تفحص الملفات الحالية وتاريخ Git المحلي ضمن حدود الإعدادات (حتى المفاتيح المحذوفة من commits قديمة) بالقواعد المخصصة، مع تكامل اختياري مع Gitleaks وإشعار اختياري عبر Telegram. لا تتحقق الأداة من صلاحية أي سر عبر خدمات خارجية، ولا تعرض أو ترسل القيمة الفعلية لأي سر في أي وضع.

## التثبيت

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
chmod +x scanx
```

في Termux: `pkg install python git` ثم ثبّت المتطلبات بالطريقة نفسها. Gitleaks اختياري؛ يمكن تثبيته من مدير الحزم المناسب، لكن غيابه لا يمنع محرك القواعد المخصص من العمل.

## الاستخدام

```bash
./scanx version
./scanx doctor
./scanx rules list
./scanx rules validate
./scanx scan /path/to/repository
./scanx scan /path/to/repository --deep        # + فحص كامل سجل Git بالقواعد المخصصة
./scanx scan https://github.com/user/repo --deep   # استنساخ مؤقت، فحص، حذف تلقائي
./scanx scan /path/to/repository --no-gitleaks
./scanx scan /path/to/repository --archives
./scanx scan /path/to/repository --deep --telegram  # إرسال تقرير مُنكّر لتيليجرام
```

يعرض الفحص فقط Metadata آمنة: القاعدة والملف والسطر والخطورة والثقة والـ commit المختصر. لا تظهر القيمة السرية في الشاشة أو السجلات أو نموذج `Finding` أو رسالة Telegram تحت أي خيار. خيارات HTML وJSON مقبولة للتوافق لكنها لا تنشئ ملفات؛ مولدات التقارير ضمن Phase 5.

### رابط GitHub
يُقبل فقط `https://github.com/<owner>/<repo>` العام. يُستنسخ بكل الفروع والـ tags إلى مجلد مؤقت، يُفحص، ثم يُحذف تلقائيًا بعد انتهاء الفحص (نجح أو فشل).

### Telegram (اختياري)
أنشئ `~/.scanx/telegram.yaml` (خارج أي مستودع git، ولا تُدرجه فيه):
```yaml
enabled: true
token: "TOKEN_FROM_BOTFATHER"
chat_id: "YOUR_CHAT_ID"
```
الأداة لا تقرأ التوكن من سطر الأوامر ولا من `settings.yaml` حتى لا ينتهي به المطاف في سجل الأوامر أو في commit بالخطأ. الرسالة المُرسلة تحتوي فقط اسم القاعدة والملف والسطر والـ commit، بلا أي قيمة فعلية.

## المحركات

- **Filesystem**: recursive، يدعم الملفات المخفية، حدود الحجم والعدد والعمق، استثناء مجلدات البناء و`node_modules` و`.git`، كشف Binary، وسياسة Symlink آمنة.
- **Custom Patterns**: قواعد YAML في `rules/` تشمل AWS وGoogle وGitHub وGitLab وSlack وDiscord وStripe وقواعد كلمات المرور وConnection Strings وJWT والمفاتيح الخاصة.
- **Archives**: ZIP وTAR وTAR.GZ وTGZ وGZIP وBZIP2 دون استخراج إلى القرص، مع حدود للحجم والعدد والعمق ومنع المسارات الخطرة.
- **Gitleaks**: محرك اختياري يعمل بـ `subprocess` دون `shell=True` وبـ JSON وredaction وtimeout. إذا لم يتوفر يظهر ذلك صراحة ولا يعتبر الفحص ناجحًا باستخدامه.

## الإعدادات والأمان

عدّل `config/settings.yaml` و`config/exclusions.yaml`. الإعدادات الافتراضية مناسبة للأجهزة محدودة الموارد. لا تسمح الأداة بتفعيل `persist_secret_values` أو `network_validation`. يتم إنشاء fingerprint keyed مؤقتًا داخل الذاكرة ولا يتم حفظ المفتاح أو القيمة الأصلية.

## الاختبارات

```bash
python -m unittest discover -s tests -v
```

يفحص Git History المحلي حتى الحد الموجود في `git_history_max_commits`، ويعرض أول وآخر commit للنتيجة المجمعة. لا يشمل بعد تحليل المخاطر الزمني أو تقارير HTML/JSON المكتملة. استخدم الأداة فقط على مشاريع تملكها أو لديك تصريح لفحصها.

# siwan__kurd — پنل پروکسی تلگرام

## راه‌اندازی روی Railway
1. پروژه را در GitHub بگذار و در Railway با «Deploy from GitHub repo» بساز (Dockerfile خودکار شناسایی می‌شود).
2. در Variables این‌ها را بگذار:
   - `ADMIN_USER` و `ADMIN_PASS` (حتماً رمز قوی)
   - `SECRET_KEY` (یک متن تصادفی بلند)
   - `PROXY_HOST` و `PROXY_PORT` (مرحله ۵)
3. در Settings → Networking یک **Public Domain** بساز (برای پنل و صفحه اشتراک؛ پورت ۸۰۰۰ یا همان `PORT`).
4. در همان بخش یک **TCP Proxy** روی پورت **8443** بساز.
5. دامنه و پورتی که Railway به TCP Proxy می‌دهد را در `PROXY_HOST` و `PROXY_PORT` بگذار و Redeploy کن.
6. یک **Volume** به مسیر `/data` وصل کن تا کاربران بعد از هر دیپلوی پاک نشوند.

## استفاده
- پنل: `https://دامنه-تو/admin`
- هر کاربر یک لینک اشتراک دارد: `https://دامنه-تو/sub/...` با حجم باقی‌مانده و دکمه اتصال.
- تغییرات (غیرفعال کردن، تمام شدن حجم، انقضا) تا ۵ ثانیه بعد روی پروکسی اعمال می‌شود.

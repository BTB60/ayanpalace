# Ayan Palace – Serverli QR Menyu

Bu versiya əvvəlki localStorage prototipindən fərqli olaraq PostgreSQL verilənlər bazası və server tərəfli admin autentifikasiyası ilə işləyir. Eyni domen üzərindən açıldığı üçün bir cihazda edilən menyu dəyişikliyi digər telefonlarda da görünür.

## Funksiyalar
- Müştəri QR menyusu: AZ / RU / EN
- Kateqoriya və məhsul siyahısı, axtarış, şəkil URL, qiymət və açıqlama
- Admin login: serverdə yoxlanılır, bcrypt hash və HttpOnly cookie/JWT
- Məhsul və kateqoriya əlavə/redaktə/silmə
- Məhsulu menyuda aktiv/deaktiv saxlamaq üçün API sahəsi
- QR kod yaratmaq və çap etmək
- PostgreSQL schema avtomatik tətbiq olunur; ilk kateqoriyalar avtomatik yaradılır

## Lokal işə salmaq
1. Node.js 20+ və PostgreSQL quraşdırın.
2. Bu qovluqda `.env.example` faylını `.env` adı ilə kopyalayın.
3. `DATABASE_URL`, `JWT_SECRET` (ən azı 32 simvol) və `ADMIN_PASSWORD` dəyərlərini doldurun.
4. Terminalda:
   ```bash
   npm install
   npm start
   ```
5. Brauzerdə `http://localhost:3000` açın. Admin istifadəçi adı `.env`-də `ADMIN_USERNAME` (default `admin`), şifrə isə `ADMIN_PASSWORD`-dur.

## Render + Neon ilə yayımlamaq
1. Neon-da PostgreSQL project/database yaradın və pooled və ya direct connection string-i götürün. SSL aktiv olmalıdır.
2. GitHub-da bu qovluğu yeni repository-yə yükləyin.
3. Render-də **New → Web Service** seçib repository-ni qoşun.
4. Build command: `npm install`; Start command: `npm start`.
5. Render Environment bölməsində:
   - `DATABASE_URL` = Neon connection string
   - `JWT_SECRET` = uzun, təsadüfi, gizli dəyər (ən azı 32 simvol)
   - `ADMIN_USERNAME` = admin istifadəçi adı
   - `ADMIN_PASSWORD` = güclü admin şifrəsi
   - `NODE_ENV` = production
6. Deploy edin. `https://SIZIN-SERVIS.onrender.com/api/health` ünvanı `{"ok":true,"database":"connected"}` qaytarmalıdır.
7. Açılan Render URL-ni QR bölməsinə daxil edin və QR yaradın.

`render.yaml` Blueprint üçün ilkin konfiqurasiya nümunəsidir. Environment secret-ləri Render panelində doldurun.

## Vacib istehsal qeydləri
- Demo admin şifrəsi yoxdur. İlk admin girişini yalnız server environment dəyişənləri müəyyən edir.
- Məhsul şəkilləri hazırda xarici HTTPS URL kimi saxlanılır. Şəkilləri admin paneldən fayl kimi yükləmək bu versiyaya daxil deyil; daimi fayl saxlama üçün Cloudinary/S3 kimi storage inteqrasiyası əlavə olunmalıdır.
- Bu QR menyu sifariş qəbul etmir; yalnız menyu göstərir və admin idarəetməsi edir.
- İstifadədən əvvəl real məhsul siyahısı, qiymətlər və şəkilləri admin paneldən daxil edin.
- DB backup və admin şifrəsinin təhlükəsiz saxlanması vacibdir.

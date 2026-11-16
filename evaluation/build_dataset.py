"""
PhishGuard-AI — Malaysian Evaluation Set Builder.
==================================================

Writes ``evaluation/datasets/malaysia_eval_v1.jsonl``: a hand-curated,
labelled benchmark of 120 page samples used to measure the end-to-end
detection pipeline on Malaysian content.

Important caveats (also stated in the dissertation):

* The page text of every sample was **authored for this benchmark**. It is
  modelled on publicly reported Malaysian scam patterns and on the general
  style of legitimate local websites; it is not scraped page content.
* URLs of malicious samples are fictitious. URLs of legitimate samples use
  the real public domain of the organisation so that the URL-based BERT
  classifier is exercised on realistic hostnames.
* Samples are split 50/50 into ``dev`` (used while tuning the rule layer)
  and ``holdout`` (never inspected during tuning) to expose over-fitting.
* "Mule" samples reference account numbers that exist in the seeded
  ``mule_registry`` table, which is itself simulated data.
* Each sample is rendered as a small HTML document. Pages that would
  realistically present a credential or payment form (login portals,
  phishing clones, a forum with a member login box) carry that form in the
  markup, because the presence of a password / OTP / card field is a signal
  the pipeline inspects. Form assignment follows the page's nature, not
  its label: legitimate login pages carry forms too.

Run:  python -m evaluation.build_dataset
"""

from __future__ import annotations

import json
from pathlib import Path

OUT_PATH = Path(__file__).parent / "datasets" / "malaysia_eval_v1.jsonl"

LEGIT, MALICIOUS = 0, 1

# (category, label, url, text)
SAMPLES: list[tuple[str, int, str, str]] = [
    # ------------------------------------------------------------------
    # L1 — Official Malaysian financial / government portals
    # ------------------------------------------------------------------
    ("L1_official_portal", LEGIT, "https://www.maybank2u.com.my/home/m2u/common/login.do",
     "Maybank2u Online Banking. Log in with your username and password. Never share your TAC or Secure2u approval with anyone."),
    ("L1_official_portal", LEGIT, "https://www.cimbclicks.com.my/clicks/",
     "CIMB Clicks. Enter your User ID to log in. Security reminder: CIMB will never ask for your password or TAC through SMS or email."),
    ("L1_official_portal", LEGIT, "https://www.pbebank.com/",
     "PBe Online Banking. Login with your User ID and password. Keep your PAC number confidential at all times."),
    ("L1_official_portal", LEGIT, "https://onlinebanking.rhbgroup.com/my/login",
     "RHB Online Banking. Username. Password. First time login? Register here. Forgot your password?"),
    ("L1_official_portal", LEGIT, "https://s.hongleongconnect.my/rib/app/fo/login",
     "Hong Leong Connect. Welcome. Please enter your username to login to online banking."),
    ("L1_official_portal", LEGIT, "https://ambank.amonline.com.my/web",
     "AmOnline. Log in to your AmBank account. Username. Password. Security alert: do not click on links in suspicious SMS."),
    ("L1_official_portal", LEGIT, "https://www.bankislam.biz/",
     "Bank Islam Internet Banking. Log masuk. ID Pengguna. Kata laluan. Jangan dedahkan TAC anda kepada sesiapa."),
    ("L1_official_portal", LEGIT, "https://www.irakyat.com.my/",
     "iRakyat Internet Banking Bank Rakyat. Sila masukkan ID pengguna dan kata laluan anda untuk log masuk."),
    ("L1_official_portal", LEGIT, "https://www.mybsn.com.my/mybsn/login/login.do",
     "myBSN Internet Banking. Login. Enter your username. Bank Simpanan Nasional will never request your OTP by phone."),
    ("L1_official_portal", LEGIT, "https://www.touchngo.com.my/",
     "Touch 'n Go eWallet. Pay, reload and manage your card. Download the app. Learn about GO+ and PayDirect."),
    ("L1_official_portal", LEGIT, "https://mytax.hasil.gov.my/",
     "MyTax Lembaga Hasil Dalam Negeri Malaysia. Log masuk menggunakan nombor pengenalan dan kata laluan. e-Filing. Semakan bayaran balik cukai."),
    ("L1_official_portal", LEGIT, "https://secure.kwsp.gov.my/member/login",
     "KWSP i-Akaun (Ahli). Log masuk. ID Pengguna. Kata laluan. Daftar i-Akaun. Lupa kata laluan?"),
    ("L1_official_portal", LEGIT, "https://www.bnm.gov.my/financial-consumer-alert",
     "Bank Negara Malaysia Financial Consumer Alert List. Companies and websites which are neither authorised nor approved under the relevant laws."),
    ("L1_official_portal", LEGIT, "https://semakmule.rmp.gov.my/",
     "Semak Mule PDRM. Semak nombor akaun bank atau nombor telefon yang disyaki terlibat dalam jenayah komersil sebelum membuat transaksi."),

    # ------------------------------------------------------------------
    # L2 — Benign third-party pages that merely mention banks / brands
    # ------------------------------------------------------------------
    ("L2_benign_brand_mention", LEGIT, "https://ringgitplus.com/en/blog/bank-news/maybank-revises-fixed-deposit-rates.html",
     "Maybank has revised its fixed deposit rates this month. Here is how the new rates compare with CIMB, Public Bank and RHB for a 12-month tenure."),
    ("L2_benign_brand_mention", LEGIT, "https://www.imoney.my/articles/best-savings-accounts-malaysia",
     "We compare the best savings accounts in Malaysia. Hong Leong Bank, AmBank and Bank Islam offer competitive profit rates for young savers."),
    ("L2_benign_brand_mention", LEGIT, "https://forum.lowyat.net/topic/5312345",
     "Anyone else having trouble with the Maybank MAE app today? I cannot log in since morning, it keeps asking for my password again. CIMB app works fine."),
    ("L2_benign_brand_mention", LEGIT, "https://soyacincau.com/2026/03/14/touch-n-go-ewallet-new-security-feature/",
     "Touch 'n Go eWallet is rolling out a new security feature that requires a 6-digit PIN before every transfer above RM250, the company announced."),
    ("L2_benign_brand_mention", LEGIT, "https://says.com/my/tech/how-to-spot-fake-bank-sms",
     "Scammers send SMS claiming your bank account is suspended. Maybank, CIMB and Public Bank all confirm they never send links asking you to verify your account."),
    ("L2_benign_brand_mention", LEGIT, "https://vulcanpost.com/865432/duitnow-qr-adoption-malaysia-sme/",
     "DuitNow QR adoption among small businesses doubled last year according to PayNet. Hawkers say customers prefer scanning over cash."),
    ("L2_benign_brand_mention", LEGIT, "https://amanz.my/2026402112/",
     "Maybank memperkenalkan ciri keselamatan baharu dalam aplikasi MAE. Pengguna perlu mengesahkan transaksi melalui Secure2u dan bukan lagi TAC melalui SMS."),
    ("L2_benign_brand_mention", LEGIT, "https://www.malaymail.com/news/money/2026/02/11/rhb-posts-higher-quarterly-profit/165432",
     "RHB Bank Bhd posted a higher net profit for the fourth quarter, driven by loan growth and lower impairment. The board declared a final dividend."),
    ("L2_benign_brand_mention", LEGIT, "https://theedgemalaysia.com/node/745123",
     "Public Bank's online banking platform PBe will undergo scheduled maintenance on Sunday. Customers are advised to plan their transfers in advance."),
    ("L2_benign_brand_mention", LEGIT, "https://www.bernama.com/en/crime_courts/news.php?id=2345678",
     "Police said the victim transferred RM48,000 to three mule accounts after receiving a call from a man claiming to be a PDRM officer. The public is urged to check accounts on Semak Mule."),
    ("L2_benign_brand_mention", LEGIT, "https://www.comparehero.my/credit-card/cimb",
     "Compare CIMB credit cards. Cash back, travel and petrol cards. Apply online and get approval in minutes. Minimum income RM24,000 per annum."),
    ("L2_benign_brand_mention", LEGIT, "https://loanstreet.com.my/learning-centre/how-to-reset-maybank2u-password",
     "Forgot your Maybank2u password? This guide explains how to reset it: go to the official site, click Forgot Login Details, then enter your card number and PIN."),
    ("L2_benign_brand_mention", LEGIT, "https://technave.com/gadget/PayPal-to-end-support-for-older-Android-versions-34521.html",
     "PayPal will end support for older Android versions next quarter. Users should update the app to continue to log in and send payments."),
    ("L2_benign_brand_mention", LEGIT, "https://mypf.my/2026/01/20/epf-account-3-withdrawal-guide/",
     "A step-by-step guide to withdrawing from EPF Account 3 through the KWSP i-Akaun app, including how the money is credited to your Maybank or CIMB savings account."),
    ("L2_benign_brand_mention", LEGIT, "https://cilisos.my/why-do-malaysian-banks-keep-warning-about-apk-scams/",
     "Why do banks like Hong Leong and AmBank keep warning us about APK scams? We asked a security researcher how fake apps steal your OTP."),
    ("L2_benign_brand_mention", LEGIT, "https://www.hmetro.com.my/mutakhir/2026/04/1123456/warga-emas-rugi-rm120000",
     "Seorang warga emas kerugian RM120,000 selepas diperdaya panggilan menyamar pegawai bank. Mangsa diarah memindahkan wang ke akaun pihak ketiga."),
    ("L2_benign_brand_mention", LEGIT, "https://www.sinarharian.com.my/article/712345/berita/semasa/lhdn-nafi-hantar-emel-bayaran-balik",
     "LHDN menafikan menghantar e-mel meminta pembayar cukai mengemas kini maklumat perbankan untuk bayaran balik cukai. Orang ramai dinasihatkan berwaspada."),
    ("L2_benign_brand_mention", LEGIT, "https://www.astroawani.com/berita-bisnes/bank-islam-lancar-akaun-digital-baharu-456789",
     "Bank Islam melancarkan akaun digital baharu yang boleh dibuka sepenuhnya melalui telefon pintar tanpa perlu hadir ke cawangan."),
    ("L2_benign_brand_mention", LEGIT, "https://paultan.org/2026/05/02/car-loan-interest-rates-malaysia-compared/",
     "Car loan interest rates compared: Public Bank, Maybank, CIMB and Hong Leong hire purchase rates for new national and non-national cars."),
    ("L2_benign_brand_mention", LEGIT, "https://www.nbc.com.my/blog/panduan-bayar-zakat-online-melalui-fpx/",
     "Panduan membayar zakat secara online melalui FPX. Pilih bank anda seperti Maybank2u, CIMB Clicks atau Bank Islam dan log masuk di laman rasmi bank."),

    # ------------------------------------------------------------------
    # L3 — General benign Malaysian / regional sites (no bank context)
    # ------------------------------------------------------------------
    ("L3_general_benign", LEGIT, "https://www.secretrecipe.com.my/menu/cakes",
     "Our signature cakes. Chocolate Indulgence, Marble Cheese and Durian Cheese. Order online for delivery or self pick-up at your nearest outlet."),
    ("L3_general_benign", LEGIT, "https://www.popular.com.my/eshop/account/login",
     "POPULAR Online. Member login. Email address. Password. New customer? Create an account to enjoy member prices on books and stationery."),
    ("L3_general_benign", LEGIT, "https://www.airasia.com/en/gb",
     "Book cheap flights, hotels and activities. Log in to your account to manage bookings, check in online and collect points."),
    ("L3_general_benign", LEGIT, "https://www.maxis.com.my/en/personal/",
     "Maxis postpaid and home fibre plans. Sign in to pay your bill, check data usage and upgrade your device."),
    ("L3_general_benign", LEGIT, "https://unifi.com.my/personal/home/broadband",
     "unifi Home broadband from RM89 per month. Check coverage at your address and sign up online today."),
    ("L3_general_benign", LEGIT, "https://www.senheng.com.my/computers-laptops.html",
     "Laptops and computers. Free delivery within Klang Valley. 0% instalment plans available for selected credit cards."),
    ("L3_general_benign", LEGIT, "https://www.zalora.com.my/women/clothing/",
     "Shop women's clothing online. New arrivals every day. Free returns within 30 days. Log in to see your wishlist."),
    ("L3_general_benign", LEGIT, "https://www.jobstreet.com.my/information-security-jobs",
     "Information security jobs in Malaysia. SOC analyst, penetration tester and GRC consultant vacancies. Sign in to apply with your profile."),
    ("L3_general_benign", LEGIT, "https://www.tgv.com.my/movies",
     "Now showing and coming soon. Buy movie tickets online and choose your seats. Sign in for member rewards."),
    ("L3_general_benign", LEGIT, "https://www.watsons.com.my/health/c/2",
     "Health and wellness products. Vitamins, supplements and personal care. Members collect points with every purchase."),
    ("L3_general_benign", LEGIT, "https://www.pos.com.my/send/track-trace",
     "Track and trace. Enter your tracking number to check the delivery status of your parcel."),
    ("L3_general_benign", LEGIT, "https://www.klook.com/en-MY/city/49-kuala-lumpur-things-to-do/",
     "Things to do in Kuala Lumpur. Petronas Twin Towers tickets, Genting day tours and airport transfers. Log in to view your bookings."),
    ("L3_general_benign", LEGIT, "https://www.utar.edu.my/admission.php",
     "Admissions. Programmes offered, entry requirements and application deadlines for the upcoming intake. Apply online through the student portal."),
    ("L3_general_benign", LEGIT, "https://rasamalaysia.com/nasi-lemak-recipe/",
     "Nasi lemak recipe. Fragrant coconut rice served with sambal, fried anchovies, peanuts and a boiled egg. Pin this recipe for later."),

    # ------------------------------------------------------------------
    # L4 — Legitimate pages that display bank account / phone numbers
    # ------------------------------------------------------------------
    ("L4_benign_with_accounts", LEGIT, "https://www.mercy.org.my/donate/",
     "Support our humanitarian work. Donate by bank transfer to MERCY Malaysia, Maybank account 562179504126. Receipts are tax exempt."),
    ("L4_benign_with_accounts", LEGIT, "https://www.spca.org.my/how-to-help/donate",
     "Donations can be banked in to SPCA Selangor, Public Bank account 3187654321. Email the transaction slip for an official receipt."),
    ("L4_benign_with_accounts", LEGIT, "https://www.masjidwilayah.gov.my/tabung-infaq",
     "Tabung infaq masjid. Sumbangan boleh disalurkan ke akaun Bank Islam 14023010045678 atas nama Masjid Wilayah Persekutuan."),
    ("L4_benign_with_accounts", LEGIT, "https://www.sjkcchunghwa.edu.my/pibg/yuran-2026",
     "Yuran PIBG 2026. Ibu bapa boleh membuat bayaran ke akaun CIMB 8600455123 dan menghantar resit kepada guru kelas."),
    ("L4_benign_with_accounts", LEGIT, "https://www.klrunners.my/events/charity-run-2026/register",
     "Charity Run 2026 registration. Fee RM60. Pay to KL Runners Club, RHB account 21412900087654 and upload proof of payment."),
    ("L4_benign_with_accounts", LEGIT, "https://www.tanbrothershardware.com.my/contact",
     "Tan Brothers Hardware Sdn Bhd. Call 03-80761234 or WhatsApp 017-6543210. Company account for trade customers: Hong Leong Bank 23400567891."),
    ("L4_benign_with_accounts", LEGIT, "https://www.homestaycameron.my/tempahan",
     "Tempahan homestay Cameron Highlands. Deposit RM100 ke akaun Maybank 164025551234 atas nama pemilik. Hubungi 019-3324567 untuk pengesahan."),
    ("L4_benign_with_accounts", LEGIT, "https://www.akademitenis.com.my/fees",
     "Monthly coaching fees RM180. Bank in to AmBank account 8881023456789 before the 5th of each month. Contact coach at 012-9087654."),
    ("L4_benign_with_accounts", LEGIT, "https://www.printcepat.my/invoice/INV-20260418",
     "Invoice INV-20260418. Amount due RM342.50. Payment by online transfer to Print Cepat Enterprise, CIMB 7613345567123. Order reference 20260418001."),
    ("L4_benign_with_accounts", LEGIT, "https://www.persatuanpenduduktamanmelati.org/yuran-keselamatan",
     "Yuran keselamatan bulanan RM50 serumah. Bayaran ke akaun persatuan di Public Bank 3220987654. Sila nyatakan nombor rumah sebagai rujukan."),
    ("L4_benign_with_accounts", LEGIT, "https://www.dewanserbaguna-pj.my/booking",
     "Hall booking. Rental RM800 per day with a refundable deposit of RM200. Tracking ID 2026051700123. Enquiries 03-79561122."),
    ("L4_benign_with_accounts", LEGIT, "https://www.kedaibukuilmu.my/checkout/manual-transfer",
     "Manual transfer. Please transfer the total to Kedai Buku Ilmu, Bank Rakyat 220987612345, then enter your order number 100245 on this page."),

    # ------------------------------------------------------------------
    # P1 — Look-alike bank portals harvesting credentials (English)
    # ------------------------------------------------------------------
    ("P1_bank_lookalike", MALICIOUS, "http://maybank2u-secure-login.top/m2u/login",
     "Maybank2u. Your account access has been limited. Log in with your username and password and enter the TAC sent to your phone to restore access."),
    ("P1_bank_lookalike", MALICIOUS, "https://rnaybank2u.com/home/login",
     "Welcome to Maybank2u Online Banking. Username. Password. For your security please confirm your Secure2u code on the next page."),
    ("P1_bank_lookalike", MALICIOUS, "http://maybznk2u.com.my/auth/login",
     "Maybank2u login. Unusual sign-in activity was detected. Verify your identity now to avoid account suspension."),
    ("P1_bank_lookalike", MALICIOUS, "https://cimbclicks-auth.top/clicks/login",
     "CIMB Clicks. Enter your User ID and password. A security verification code will be requested to reactivate your account."),
    ("P1_bank_lookalike", MALICIOUS, "http://cimb-clicks-verify.net/update",
     "Dear CIMB customer, your Clicks ID will expire today. Update your login details and TAC number immediately to continue using online banking."),
    ("P1_bank_lookalike", MALICIOUS, "http://pbebank-update-info.net/login",
     "PBe Online Banking. Your PAC has expired. Login and enter your new PAC and card number to avoid temporary freeze."),
    ("P1_bank_lookalike", MALICIOUS, "https://pbbank-online.xyz/pbe/secure",
     "Public Bank security centre. We noticed an unauthorized login. Confirm your identity by entering your User ID, password and PAC."),
    ("P1_bank_lookalike", MALICIOUS, "http://rhb-online-verify.net/auth",
     "RHB Online Banking verification. Username. Password. Enter the OTP sent to your mobile to complete the verification."),
    ("P1_bank_lookalike", MALICIOUS, "https://hlb-connect-secure.com/rib/login",
     "Hong Leong Connect. Your device is not recognised. Please log in and key in your TAC code to register this device."),
    ("P1_bank_lookalike", MALICIOUS, "http://ambank-amonline-secure.top/web/login",
     "AmOnline security update. Sign in with your username and password. Failure to update within 24 hours will result in account suspension."),
    ("P1_bank_lookalike", MALICIOUS, "https://bankislam-secure-login.net/ib",
     "Bank Islam Internet Banking. Log masuk. Masukkan ID pengguna, kata laluan dan nombor TAC anda untuk pengesahan keselamatan."),
    ("P1_bank_lookalike", MALICIOUS, "http://login.maybank2u.com.my.session-verify.info/m2u",
     "Maybank2u. Session expired. Please re-authenticate with your username, password and Secure TAC to continue."),
    ("P1_bank_lookalike", MALICIOUS, "http://185.203.118.44/maybank2u/login.php",
     "Maybank2u Online Banking. Username. Password. Login."),
    ("P1_bank_lookalike", MALICIOUS, "https://xn--mybank2u-n4a.com/login",
     "Maybank2u. Log in to your account. Enter your username and password."),

    # ------------------------------------------------------------------
    # P2 — Bahasa Melayu / Manglish government & utility lures
    # ------------------------------------------------------------------
    ("P2_bm_manglish_lure", MALICIOUS, "http://lhdn-refund-my.com/tuntutan",
     "LHDN: Anda layak menerima bayaran balik cukai sebanyak RM1,284.60. Sila kemaskini maklumat perbankan dan masukkan nombor kad serta kata laluan untuk tuntutan."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://pdrm-saman-online.net/semak",
     "PDRM: Anda mempunyai saman tertunggak. Bayar dalam masa 24 jam untuk elak tindakan mahkamah. Log masuk perbankan internet anda untuk membuat bayaran."),
    ("P2_bm_manglish_lure", MALICIOUS, "https://kwsp-ikaun-pengeluaran.xyz/login",
     "KWSP i-Akaun. Pengeluaran khas RM10,000 kini dibuka. Log masuk dengan ID pengguna dan kata laluan, kemudian masukkan TAC untuk pengesahan."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://bantuan-str-2026.top/mohon",
     "Tuntutan bantuan tunai STR 2026 sebanyak RM500. Isi nama, nombor kad pengenalan, nama bank dan kata laluan perbankan internet untuk kredit segera."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://jpj-saman-diskaun.click/bayar",
     "JPJ: Diskaun saman 70% tamat hari ini. Tindakan segera diperlukan. Pilih bank anda dan log masuk untuk bayar sekarang."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://tnb-bil-tertunggak.cc/semakan",
     "TNB: Bekalan elektrik anda akan dipotong hari ini kerana bil tertunggak RM86.40. Bayar segera melalui pautan ini dengan kad debit anda."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://pos-malaysia-parcel-held.top/track",
     "Pos Malaysia: Bungkusan anda ditahan kerana alamat tidak lengkap. Bayar caj penghantaran semula RM2.99. Masukkan nombor kad, tarikh luput dan kod OTP."),
    ("P2_bm_manglish_lure", MALICIOUS, "https://akaun-dibekukan-bnm.net/pengesahan",
     "Bank Negara Malaysia: Akaun anda dibekukan kerana disyaki terlibat pengubahan wang haram. Buat pengesahan keselamatan dan pindahkan baki ke akaun selamat."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://mysejahtera-subsidi.buzz/claim",
     "Subsidi petrol bersasar RM200 sebulan. Tuntut sekarang sebelum kuota penuh. Log masuk menggunakan akaun bank anda untuk pengesahan identiti."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://eh-bro-claim-angpow.fit/tng",
     "Eh bro, TNG kasi free angpow RM88 lah! Cepat claim before habis. Key in your phone number, 6-digit PIN and the OTP you receive, confirm masuk one."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://mahkamah-notis-rasmi.work/kes",
     "Notis mahkamah: Nama anda terlibat dalam kes penipuan. Hubungi pegawai penyiasat dan sahkan identiti anda dengan nombor kad ATM dan PIN."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://e-wallet-bantuan-rakyat.club/daftar",
     "Bantuan e-wallet RM300 untuk semua rakyat Malaysia. Daftar sekarang. Masukkan nombor telefon, kata laluan e-wallet dan kod pengesahan."),
    ("P2_bm_manglish_lure", MALICIOUS, "https://semakan-cukai-tertunggak.surf/lhdn",
     "Cukai LHDN tertunggak RM3,410. Elak sekatan perjalanan. Bayar sekarang melalui FPX: pilih bank dan masukkan ID serta kata laluan."),
    ("P2_bm_manglish_lure", MALICIOUS, "http://zhanghu-anquan-yanzheng.top/my",
     "紧急通知:您的银行账户冻结。请立即验证您的身份并输入密码和验证码以解除冻结。"),

    # ------------------------------------------------------------------
    # P3 — Pages soliciting payment into registered mule accounts
    # ------------------------------------------------------------------
    ("P3_mule_account", MALICIOUS, "http://murah-gadget-store.com/iphone-15-pro",
     "iPhone 15 Pro Max 256GB brand new sealed RM1,200 only. Cash on delivery not available. Bank in to Maybank 112233445566 and WhatsApp the receipt."),
    ("P3_mule_account", MALICIOUS, "http://sewa-bilik-kl-murah.net/listing/2231",
     "Bilik sewa Bangsar RM350 sebulan termasuk utiliti. Ramai berminat, bayar deposit RM350 dahulu ke CIMB 76001234567890 untuk tempah bilik."),
    ("P3_mule_account", MALICIOUS, "https://kerja-part-time-online.my/task",
     "Part time job, earn RM300 a day liking videos. To unlock the next task level, top up RM150 to Public Bank 3998877665. Commission paid daily."),
    ("P3_mule_account", MALICIOUS, "http://pinjaman-peribadi-lulus-segera.com/mohon",
     "Pinjaman peribadi lulus segera tanpa dokumen. Bayar yuran pemprosesan RM280 ke akaun RHB 21234567890123 dan wang dikreditkan dalam 30 minit."),
    ("P3_mule_account", MALICIOUS, "http://kucing-british-shorthair-jual.com/order",
     "British Shorthair kittens for sale RM600. Delivery nationwide by pet courier. Transfer booking fee to Hong Leong Bank 234567890123."),
    ("P3_mule_account", MALICIOUS, "http://tiket-konsert-murah.net/coldplay",
     "Concert tickets Cat 1 below market price, last 4 seats. Pay full amount to AmBank 8123456789012. E-ticket emailed after payment."),
    ("P3_mule_account", MALICIOUS, "http://pelaburan-emas-patuh-syariah.com/daftar",
     "Pelaburan emas patuh syariah, pulangan 30% dalam 7 hari dijamin. Modal minimum RM500 ke akaun Bank Islam 14001234567890."),
    ("P3_mule_account", MALICIOUS, "http://ps5-clearance-warehouse.com/deal",
     "Warehouse clearance PS5 console RM899. Limited units. Payment by bank transfer only to Maybank 156789012345."),
    ("P3_mule_account", MALICIOUS, "http://kedai-perabot-online-murah.com/sofa",
     "Sofa L-shape promosi RM499 penghantaran percuma. Bayaran penuh ke Public Bank 3567891234 sebelum penghantaran."),
    ("P3_mule_account", MALICIOUS, "http://agent-tiket-bas-ekspres.net/raya",
     "Tiket bas ekspres balik kampung Raya. Tempah sekarang, transfer melalui DuitNow ke nombor 0198765432 dan hantar bukti bayaran."),
    ("P3_mule_account", MALICIOUS, "http://seller-jam-tangan-original.com/rolex",
     "Jam tangan original harga borong. Deposit RM200 ke Maybank 564738291012 atas nama ejen. Baki bayar selepas terima barang."),
    ("P3_mule_account", MALICIOUS, "https://www.homestaypenang-promo.com/book",
     "Homestay Batu Ferringhi promo cuti sekolah RM180 semalam. Bayar deposit ke CIMB 70009876543210 untuk sahkan tempahan."),

    # ------------------------------------------------------------------
    # P4 — E-wallet, payment and global-brand impersonation
    # ------------------------------------------------------------------
    ("P4_ewallet_brand", MALICIOUS, "http://tng-ewallet-cashback.top/claim",
     "Touch 'n Go eWallet cashback RM50. Claim e-wallet credit now. Enter your mobile number and 6-digit PIN to verify your account."),
    ("P4_ewallet_brand", MALICIOUS, "http://touchngo-reload-bonus.net/login",
     "TNG eWallet reload bonus. Log in with your phone number and PIN. Enter the OTP to receive RM30 bonus credit."),
    ("P4_ewallet_brand", MALICIOUS, "http://grabpay-reward-verification.top/claim",
     "GrabPay rewards. You have RM120 unclaimed. Verify your account now with your phone number and OTP code."),
    ("P4_ewallet_brand", MALICIOUS, "http://shopeepay-voucher-claim.net/free",
     "ShopeePay voucher RM100 free. Log in to your Shopee account and confirm your ShopeePay PIN to redeem."),
    ("P4_ewallet_brand", MALICIOUS, "http://duitnow-qr-refund.click/scan",
     "DuitNow refund pending. Scan the DuitNow QR code below with your banking app and approve the transaction to receive your refund."),
    ("P4_ewallet_brand", MALICIOUS, "https://paypal-my-verify.com/signin",
     "PayPal. Your account is limited. Log in and confirm your identity. Update payment method and enter your card security code."),
    ("P4_ewallet_brand", MALICIOUS, "http://netflix-billing-my.net/update",
     "Netflix. Payment failed. Update payment method within 48 hours to keep your membership. Enter card number, expiry date and CVV."),
    ("P4_ewallet_brand", MALICIOUS, "http://binance-my-airdrop.xyz/claim",
     "Binance Malaysia airdrop. Claim airdrop of 500 USDT. Connect your wallet and enter your seed phrase for wallet validation."),
    ("P4_ewallet_brand", MALICIOUS, "https://apple-id-locked-my.com/unlock",
     "Apple ID locked. Apple security alert: your Apple ID was used to sign in on a new device. Sign in to unlock your account."),
    ("P4_ewallet_brand", MALICIOUS, "http://boost-ewallet-bonus-my.rest/redeem",
     "Boost e-wallet anniversary bonus RM68. Redeem now. Masukkan nombor telefon, PIN dan kod OTP anda untuk tebus hadiah."),

    # ------------------------------------------------------------------
    # P5 — Evasive samples (neutral hostnames, shared hosting, sparse text)
    # ------------------------------------------------------------------
    ("P5_evasive", MALICIOUS, "https://secure-portal-update.com/my/auth",
     "Maybank2u. Log in to your account. Username. Password. Enter your TAC to continue."),
    ("P5_evasive", MALICIOUS, "https://customer-care-desk.net/verify",
     "CIMB Clicks customer verification. Please enter your User ID, password and the security code sent by SMS."),
    ("P5_evasive", MALICIOUS, "https://maybank2u-login.web.app/",
     "Maybank2u Online Banking. Username. Password. Log in. Enter the TAC number sent to your registered mobile."),
    ("P5_evasive", MALICIOUS, "https://cimb-clicks-verify.vercel.app/",
     "CIMB Clicks. Your account has been temporarily locked. Verify account now by entering your User ID and password."),
    ("P5_evasive", MALICIOUS, "https://pbe-secure-update.netlify.app/",
     "PBe Public Bank. Update your login details. User ID. Password. PAC number."),
    ("P5_evasive", MALICIOUS, "https://docs.google.com/forms/d/e/1FAIpQLSfakeformid/viewform",
     "Maybank account verification form. Full name. Maybank2u username. Password. ATM card number and PIN. Submit to avoid account closure."),
    ("P5_evasive", MALICIOUS, "http://form-submit-online.site/m2u",
     "Loading secure session..."),
    ("P5_evasive", MALICIOUS, "https://hr-payroll-notice.com/payslip",
     "Your payslip is ready. Sign in with your Microsoft 365 email and password to view the document. Session will expire in 10 minutes."),
    ("P5_evasive", MALICIOUS, "https://smart-invest-daily.com/join",
     "Join our investment group. Guaranteed profit 15% daily managed by licensed traders. Deposit a minimum of RM1,000 today and withdraw anytime."),
    ("P5_evasive", MALICIOUS, "https://parcel-redelivery-my.com/pay",
     "Your parcel could not be delivered. Customs fee unpaid RM4.50. Pay now with your debit card to schedule redelivery."),
]


# Sample numbers (1-based, in SAMPLES order) whose page presents a form.
_LOGIN_FORM = (set(range(1, 10)) | {11, 12, 17, 36} | set(range(61, 75))
               | {75, 76, 77, 78, 79, 83, 86, 87, 88, 102, 104, 106, 109}
               | {111, 112, 113, 114, 115, 118})
_OTP_FORM = {84, 101, 103, 110}
_CARD_FORM = {80, 81, 107, 120}

_FORMS = {
    "login": ('<form method="post"><label>Username</label><input type="text" name="username">'
              '<label>Password</label><input type="password" name="password">'
              '<button type="submit">Log in</button></form>'),
    "otp": ('<form method="post"><label>Mobile number</label><input type="tel" name="phone">'
            '<label>PIN</label><input type="password" name="pin" maxlength="6">'
            '<label>OTP</label><input type="text" name="otp" autocomplete="one-time-code">'
            '<button type="submit">Submit</button></form>'),
    "card": ('<form method="post"><label>Card number</label><input type="text" name="cardnumber" autocomplete="cc-number">'
             '<label>Expiry</label><input type="text" name="exp" autocomplete="cc-exp">'
             '<label>CVV</label><input type="text" name="cvv" autocomplete="cc-csc">'
             '<button type="submit">Pay</button></form>'),
}


def _form_kind(index: int) -> str:
    if index in _LOGIN_FORM:
        return "login"
    if index in _OTP_FORM:
        return "otp"
    if index in _CARD_FORM:
        return "card"
    return "none"


def build() -> int:
    """Write the JSONL file and return the number of samples written."""
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    per_category_counter: dict[str, int] = {}
    with OUT_PATH.open("w", encoding="utf-8") as fh:
        for index, (category, label, url, text) in enumerate(SAMPLES, start=1):
            seen = per_category_counter.get(category, 0)
            per_category_counter[category] = seen + 1
            form = _form_kind(index)
            html = (f"<html><head><title>{text.split('.')[0][:60]}</title></head><body><main><p>{text}</p>"
                    f"{_FORMS.get(form, '')}</main></body></html>")
            record = {
                "id": f"MY-{index:03d}",
                # Alternate within each category so both splits are balanced.
                "split": "dev" if seen % 2 == 0 else "holdout",
                "category": category,
                "label": label,
                "url": url,
                "text": text,
                "form": form,
                "html": html,
            }
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return len(SAMPLES)


if __name__ == "__main__":
    total = build()
    print(f"Wrote {total} samples to {OUT_PATH}")

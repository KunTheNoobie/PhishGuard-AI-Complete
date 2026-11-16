# Malaysian benchmark results — `baseline_v3.0.0` (v3.0.0)

Samples: 120 (60 malicious, 60 legitimate). Device: cpu. BERT threshold: 0.75.

## Pipeline verdict (BLOCK_RENDER vs SAFE)

| Split | n | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|---|
| overall | 120 | 56 | 47 | 4 | 13 | 0.5750 | 0.5437 | 0.9333 | 0.6871 | 0.7833 |
| dev | 60 | 28 | 23 | 2 | 7 | 0.5833 | 0.5490 | 0.9333 | 0.6914 | 0.7667 |
| holdout | 60 | 28 | 24 | 2 | 6 | 0.5667 | 0.5385 | 0.9333 | 0.6829 | 0.8000 |

## Pipeline accuracy per category

| Category | n | Correct | Blocked | Accuracy |
|---|---|---|---|---|
| L1_official_portal | 14 | 10 | 4 | 0.7143 |
| L2_benign_brand_mention | 20 | 0 | 20 | 0.0000 |
| L3_general_benign | 14 | 1 | 13 | 0.0714 |
| L4_benign_with_accounts | 12 | 2 | 10 | 0.1667 |
| P1_bank_lookalike | 14 | 14 | 14 | 1.0000 |
| P2_bm_manglish_lure | 14 | 14 | 14 | 1.0000 |
| P3_mule_account | 12 | 12 | 12 | 1.0000 |
| P4_ewallet_brand | 10 | 10 | 10 | 1.0000 |
| P5_evasive | 10 | 6 | 6 | 0.6000 |

## BERT-only (no rule layer)

| Input formulation | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| composite | 0.5000 | 0.5000 | 1.0000 | 0.6667 | 1.0000 | 0.7037 |
| url_raw | 0.5333 | 0.5185 | 0.9333 | 0.6667 | 0.8667 | 0.7596 |
| url_stripped | 0.7250 | 0.6709 | 0.8833 | 0.7626 | 0.4333 | 0.8599 |

## In-process latency (ms)

- All requests: mean 138.77, p50 145.48, p95 244.53, max 408.77
- BERT path (n=103): mean 161.59, p50 149.4, p95 275.33
- Whitelist bypass (n=17): mean 0.47

## Misclassified samples (51)

- MY-006 (L1_official_portal, false positive): https://ambank.amonline.com.my/web
- MY-007 (L1_official_portal, false positive): https://www.bankislam.biz/
- MY-008 (L1_official_portal, false positive): https://www.irakyat.com.my/
- MY-009 (L1_official_portal, false positive): https://www.mybsn.com.my/mybsn/login/login.do
- MY-015 (L2_benign_brand_mention, false positive): https://ringgitplus.com/en/blog/bank-news/maybank-revises-fixed-deposit-rates.html
- MY-016 (L2_benign_brand_mention, false positive): https://www.imoney.my/articles/best-savings-accounts-malaysia
- MY-017 (L2_benign_brand_mention, false positive): https://forum.lowyat.net/topic/5312345
- MY-018 (L2_benign_brand_mention, false positive): https://soyacincau.com/2026/03/14/touch-n-go-ewallet-new-security-feature/
- MY-019 (L2_benign_brand_mention, false positive): https://says.com/my/tech/how-to-spot-fake-bank-sms
- MY-020 (L2_benign_brand_mention, false positive): https://vulcanpost.com/865432/duitnow-qr-adoption-malaysia-sme/
- MY-021 (L2_benign_brand_mention, false positive): https://amanz.my/2026402112/
- MY-022 (L2_benign_brand_mention, false positive): https://www.malaymail.com/news/money/2026/02/11/rhb-posts-higher-quarterly-profit/165432
- MY-023 (L2_benign_brand_mention, false positive): https://theedgemalaysia.com/node/745123
- MY-024 (L2_benign_brand_mention, false positive): https://www.bernama.com/en/crime_courts/news.php?id=2345678
- MY-025 (L2_benign_brand_mention, false positive): https://www.comparehero.my/credit-card/cimb
- MY-026 (L2_benign_brand_mention, false positive): https://loanstreet.com.my/learning-centre/how-to-reset-maybank2u-password
- MY-027 (L2_benign_brand_mention, false positive): https://technave.com/gadget/PayPal-to-end-support-for-older-Android-versions-34521.html
- MY-028 (L2_benign_brand_mention, false positive): https://mypf.my/2026/01/20/epf-account-3-withdrawal-guide/
- MY-029 (L2_benign_brand_mention, false positive): https://cilisos.my/why-do-malaysian-banks-keep-warning-about-apk-scams/
- MY-030 (L2_benign_brand_mention, false positive): https://www.hmetro.com.my/mutakhir/2026/04/1123456/warga-emas-rugi-rm120000
- MY-031 (L2_benign_brand_mention, false positive): https://www.sinarharian.com.my/article/712345/berita/semasa/lhdn-nafi-hantar-emel-bayaran-balik
- MY-032 (L2_benign_brand_mention, false positive): https://www.astroawani.com/berita-bisnes/bank-islam-lancar-akaun-digital-baharu-456789
- MY-033 (L2_benign_brand_mention, false positive): https://paultan.org/2026/05/02/car-loan-interest-rates-malaysia-compared/
- MY-034 (L2_benign_brand_mention, false positive): https://www.nbc.com.my/blog/panduan-bayar-zakat-online-melalui-fpx/
- MY-035 (L3_general_benign, false positive): https://www.secretrecipe.com.my/menu/cakes
- MY-036 (L3_general_benign, false positive): https://www.popular.com.my/eshop/account/login
- MY-037 (L3_general_benign, false positive): https://www.airasia.com/en/gb
- MY-038 (L3_general_benign, false positive): https://www.maxis.com.my/en/personal/
- MY-039 (L3_general_benign, false positive): https://unifi.com.my/personal/home/broadband
- MY-040 (L3_general_benign, false positive): https://www.senheng.com.my/computers-laptops.html
- MY-041 (L3_general_benign, false positive): https://www.zalora.com.my/women/clothing/
- MY-042 (L3_general_benign, false positive): https://www.jobstreet.com.my/information-security-jobs
- MY-043 (L3_general_benign, false positive): https://www.tgv.com.my/movies
- MY-044 (L3_general_benign, false positive): https://www.watsons.com.my/health/c/2
- MY-045 (L3_general_benign, false positive): https://www.pos.com.my/send/track-trace
- MY-046 (L3_general_benign, false positive): https://www.klook.com/en-MY/city/49-kuala-lumpur-things-to-do/
- MY-048 (L3_general_benign, false positive): https://rasamalaysia.com/nasi-lemak-recipe/
- MY-049 (L4_benign_with_accounts, false positive): https://www.mercy.org.my/donate/
- MY-050 (L4_benign_with_accounts, false positive): https://www.spca.org.my/how-to-help/donate
- MY-053 (L4_benign_with_accounts, false positive): https://www.klrunners.my/events/charity-run-2026/register
- MY-054 (L4_benign_with_accounts, false positive): https://www.tanbrothershardware.com.my/contact
- MY-055 (L4_benign_with_accounts, false positive): https://www.homestaycameron.my/tempahan
- MY-056 (L4_benign_with_accounts, false positive): https://www.akademitenis.com.my/fees
- MY-057 (L4_benign_with_accounts, false positive): https://www.printcepat.my/invoice/INV-20260418
- MY-058 (L4_benign_with_accounts, false positive): https://www.persatuanpenduduktamanmelati.org/yuran-keselamatan
- MY-059 (L4_benign_with_accounts, false positive): https://www.dewanserbaguna-pj.my/booking
- MY-060 (L4_benign_with_accounts, false positive): https://www.kedaibukuilmu.my/checkout/manual-transfer
- MY-113 (P5_evasive, false negative): https://maybank2u-login.web.app/
- MY-114 (P5_evasive, false negative): https://cimb-clicks-verify.vercel.app/
- MY-115 (P5_evasive, false negative): https://pbe-secure-update.netlify.app/
- MY-116 (P5_evasive, false negative): https://docs.google.com/forms/d/e/1FAIpQLSfakeformid/viewform

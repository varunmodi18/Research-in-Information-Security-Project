# Primitive timings

Commit `1d01073` · 13th Gen Intel(R) Core(TM) i7-13620H · Linux 7.0.0-34-generic · Python 3.12.3 · 3 warm-up runs discarded per case.

Host wall-clock times of the pure-Python reference code. Not sensor-node figures.

| params | operation | iterations | median (ms) | IQR (ms) |
|---|---|---:|---:|---:|
| toy | hash_to_point (T_HG) | 200 | 0.1504 | 0.0128 |
| toy | scalar_mul (T_SM) | 200 | 0.4105 | 0.0094 |
| toy | point_add (T_PA) | 200 | 0.0143 | 0.0002 |
| toy | weil_pairing (T_P) | 200 | 4.7040 | 0.1077 |
| toy | tate_pairing (T_P alt) | 200 | 1.5581 | 0.0435 |
| toy | ibe_encrypt (T_E/D) | 200 | 5.2615 | 0.1656 |
| toy | ibe_decrypt (T_E/D) | 200 | 4.7360 | 0.1354 |
| toy | aes_gcm_encrypt_64B (T_S) | 200 | 0.0024 | 0.0001 |
| toy | kdf_sha256 (hashing.kdf) | 200 | 0.0007 | 0.0000 |
| demo | hash_to_point (T_HG) | 30 | 0.6234 | 0.0992 |
| demo | scalar_mul (T_SM) | 30 | 22.7406 | 0.1758 |
| demo | point_add (T_PA) | 30 | 0.0727 | 0.0016 |
| demo | weil_pairing (T_P) | 30 | 148.5128 | 0.2096 |
| demo | tate_pairing (T_P alt) | 30 | 65.2102 | 0.4128 |
| demo | ibe_encrypt (T_E/D) | 30 | 169.1466 | 1.0950 |
| demo | ibe_decrypt (T_E/D) | 30 | 148.2448 | 0.3530 |
| demo | aes_gcm_encrypt_64B (T_S) | 30 | 0.0025 | 0.0001 |
| demo | kdf_sha256 (hashing.kdf) | 30 | 0.0008 | 0.0000 |
| secure | hash_to_point (T_HG) | 5 | 3.4633 | 0.7133 |
| secure | scalar_mul (T_SM) | 5 | 98.2245 | 0.4430 |
| secure | point_add (T_PA) | 5 | 0.1522 | 0.0015 |
| secure | weil_pairing (T_P) | 5 | 572.6419 | 2.5585 |
| secure | tate_pairing (T_P alt) | 5 | 269.0968 | 0.0892 |
| secure | ibe_encrypt (T_E/D) | 5 | 650.7788 | 6.2020 |
| secure | ibe_decrypt (T_E/D) | 5 | 552.7578 | 0.6225 |
| secure | aes_gcm_encrypt_64B (T_S) | 5 | 0.0025 | 0.0001 |
| secure | kdf_sha256 (hashing.kdf) | 5 | 0.0009 | 0.0000 |

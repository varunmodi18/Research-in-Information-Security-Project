# Primitive timings

Commit `28e8fe6` · 13th Gen Intel(R) Core(TM) i7-13620H · Linux 7.0.0-34-generic · Python 3.12.3 · 3 warm-up runs discarded per case.

Host wall-clock times of the pure-Python reference code. Not sensor-node figures.

| params | operation | iterations | median (ms) | IQR (ms) |
|---|---|---:|---:|---:|
| toy | hash_to_point (T_HG) | 200 | 0.1556 | 0.0128 |
| toy | scalar_mul (T_SM) | 200 | 0.4235 | 0.0221 |
| toy | point_add (T_PA) | 200 | 0.0144 | 0.0002 |
| toy | weil_pairing (T_P) | 200 | 4.8788 | 0.1203 |
| toy | tate_pairing (T_P alt) | 200 | 1.5783 | 0.0191 |
| toy | ibe_encrypt (T_E/D) | 200 | 5.4601 | 0.2072 |
| toy | ibe_decrypt (T_E/D) | 200 | 4.6774 | 0.0459 |
| toy | aes_gcm_encrypt_64B (T_S) | 200 | 0.0022 | 0.0001 |
| toy | kdf_sha256 (hashing.kdf) | 200 | 0.0007 | 0.0000 |
| demo | hash_to_point (T_HG) | 30 | 0.6462 | 0.0793 |
| demo | scalar_mul (T_SM) | 30 | 22.4551 | 0.2356 |
| demo | point_add (T_PA) | 30 | 0.0731 | 0.0006 |
| demo | weil_pairing (T_P) | 30 | 157.6893 | 3.4110 |
| demo | tate_pairing (T_P alt) | 30 | 67.7484 | 0.8253 |
| demo | ibe_encrypt (T_E/D) | 30 | 177.8831 | 1.8357 |
| demo | ibe_decrypt (T_E/D) | 30 | 154.5834 | 0.6511 |
| demo | aes_gcm_encrypt_64B (T_S) | 30 | 0.0022 | 0.0001 |
| demo | kdf_sha256 (hashing.kdf) | 30 | 0.0008 | 0.0000 |
| secure | hash_to_point (T_HG) | 5 | 3.4532 | 0.6752 |
| secure | scalar_mul (T_SM) | 5 | 95.6529 | 0.1747 |
| secure | point_add (T_PA) | 5 | 0.1515 | 0.0022 |
| secure | weil_pairing (T_P) | 5 | 588.4529 | 4.6964 |
| secure | tate_pairing (T_P alt) | 5 | 281.6187 | 4.8637 |
| secure | ibe_encrypt (T_E/D) | 5 | 673.0837 | 5.3516 |
| secure | ibe_decrypt (T_E/D) | 5 | 580.0981 | 3.0609 |
| secure | aes_gcm_encrypt_64B (T_S) | 5 | 0.0026 | 0.0012 |
| secure | kdf_sha256 (hashing.kdf) | 5 | 0.0009 | 0.0001 |

## Comparison with the M0-T4 baseline (V-PERF-01; > 20 % slower is reported)

| primitive | params | baseline ms | current ms | ratio | regression |
|---|---|---:|---:|---:|---|
| hash_to_point (T_HG) | toy | 0.1504 | 0.1556 | 1.035 | no |
| scalar_mul (T_SM) | toy | 0.4105 | 0.4235 | 1.032 | no |
| point_add (T_PA) | toy | 0.0143 | 0.0144 | 1.005 | no |
| weil_pairing (T_P) | toy | 4.704 | 4.8788 | 1.037 | no |
| tate_pairing (T_P alt) | toy | 1.5581 | 1.5783 | 1.013 | no |
| ibe_encrypt (T_E/D) | toy | 5.2615 | 5.4601 | 1.038 | no |
| ibe_decrypt (T_E/D) | toy | 4.736 | 4.6774 | 0.988 | no |
| aes_gcm_encrypt_64B (T_S) | toy | 0.0024 | 0.0022 | 0.908 | no |
| kdf_sha256 (hashing.kdf) | toy | 0.0007 | 0.0007 | 0.993 | no |
| hash_to_point (T_HG) | demo | 0.6234 | 0.6462 | 1.037 | no |
| scalar_mul (T_SM) | demo | 22.7406 | 22.4551 | 0.987 | no |
| point_add (T_PA) | demo | 0.0727 | 0.0731 | 1.005 | no |
| weil_pairing (T_P) | demo | 148.5128 | 157.6893 | 1.062 | no |
| tate_pairing (T_P alt) | demo | 65.2102 | 67.7484 | 1.039 | no |
| ibe_encrypt (T_E/D) | demo | 169.1466 | 177.8831 | 1.052 | no |
| ibe_decrypt (T_E/D) | demo | 148.2448 | 154.5834 | 1.043 | no |
| aes_gcm_encrypt_64B (T_S) | demo | 0.0025 | 0.0022 | 0.886 | no |
| kdf_sha256 (hashing.kdf) | demo | 0.0008 | 0.0008 | 0.991 | no |
| hash_to_point (T_HG) | secure | 3.4633 | 3.4532 | 0.997 | no |
| scalar_mul (T_SM) | secure | 98.2245 | 95.6529 | 0.974 | no |
| point_add (T_PA) | secure | 0.1522 | 0.1515 | 0.995 | no |
| weil_pairing (T_P) | secure | 572.6419 | 588.4529 | 1.028 | no |
| tate_pairing (T_P alt) | secure | 269.0968 | 281.6187 | 1.047 | no |
| ibe_encrypt (T_E/D) | secure | 650.7788 | 673.0837 | 1.034 | no |
| ibe_decrypt (T_E/D) | secure | 552.7578 | 580.0981 | 1.049 | no |
| aes_gcm_encrypt_64B (T_S) | secure | 0.0025 | 0.0026 | 1.047 | no |
| kdf_sha256 (hashing.kdf) | secure | 0.0009 | 0.0009 | 0.998 | no |

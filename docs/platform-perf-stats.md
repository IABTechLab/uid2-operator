**Test setup: Baseline**

Azure: 8 instances (utilize 8 vCPUs), 48G Mem, non-enclave

Config: prod + 100 synthetic optout

| Endpoint          | Method | QPS   | Throughput | Avg Latency | Min Latency | 50%    | 90%     | 99%     | Client Count |
| :---------------- | :----- | :---- | :--------- | :---------- | :---------- | :----- | :------ | :------ | :----------- |
| v1/identity/map   | POST   | 1028  | 120.74MB/s | 7.99ms      | 5.02ms      | 6.66ms | 10.75ms | 23.95ms | 8            |
| v1/identity/map   | GET    | 82308 | 20.29 MB/s | 3.78ms      | 0.12ms      | 3.36ms | 4.86ms  | 13.24ms | 300          |
| v1/token/refresh  | GET    | 46247 | 28.36 MB/s | 7.04ms      | 0.20ms      | 5.48ms | 10.51ms | 27.31ms | 300          |
| v1/token/generate | GET    | 48990 | 30.04 MB/s | 6.68ms      | 0.17ms      | 5.15ms | 10.00ms | 26.99ms | 300          |



**Test setup: AWS Enclave**

AWS Nitro Enclave: 8 instances (8 vCPUs), 40G Mem

Config: prod + 100 synthetic optout

| Endpoint          | Method | QPS   | Throughput | Avg Latency | Min Latency | 50%     | 90%     | 99%     | Client Count |
| :---------------- | :----- | :---- | :--------- | :---------- | :---------- | :------ | :------ | :------ | :----------- |
| v1/identity/map   | POST   | 156   | 22.11 MB/s | 51.07ms     | 46.15ms     | 49.11ms | 53.45ms | 92.75ms | 8            |
| v1/identity/map   | GET    | 14477 | 3.42 MB/s  | 21.05ms     | 0.57ms      | 19.76ms | 39.73ms | 57.34ms | 300          |
| v1/token/refresh  | GET    | 14356 | 8.80 MB/s  | 21.32ms     | 0.64ms      | 19.69ms | 39.76ms | 59.59ms | 300          |
| v1/token/generate | GET    | 14400 | 8.83 MB/s  | 21.29ms     | 0.75ms      | 19.72ms | 39.75ms | 58.61ms | 300          |



**Test setup: GCP Secure Computing**

GCP Secure Computing: 16 instances, 64G Mem

| Endpoint          | Method | QPS   | Throughput  | Avg Latency | Min Latency | 50%    | 90%    | 99%     | Client Count |
| :---------------- | :----- | :---- | :---------- | :---------- | :---------- | :----- | :----- | :------ | :----------- |
| v1/identity/map   | POST   | 1439  | 203.25 MB/s | 5.45ms      | 4.43ms      | 5.27ms | 6.10ms | 8.47ms  | 8            |
| v1/identity/map   | GET    | 64595 | 15.92 MB/s  | 4.76ms      | 0.77ms      | 4.31ms | 8.15ms | 12.96ms | 300          |
| v1/token/refresh  | GET    | 48611 | 29.81 MB/s  | 6.19ms      | 1.06ms      | 5.41ms | 9.88ms | 13.22ms | 300          |
| v1/token/generate | GET    | 48000 | 29.43 MB/s  | 6.29ms      | 1.14ms      | 5.54ms | 9.97ms | 13.92ms | 300          |



**Test setup: Azure SGX Enclave**

Azure SGX Enclave: 8 instances (utilize 8 vCPUs), 22G Mem, 160MB EPC memory

Config: prod + 40 synthetic optout

| Endpoint          | Method | QPS  | Throughput | Avg Latency | Min Latency | 50%       | 90%       | 99%       | Client Count |
| :---------------- | :----- | :--- | :--------- | :---------- | :---------- | :-------- | :-------- | :-------- | :----------- |
| v1/identity/map   | POST   | 21   | 2.54 MB/s  | 371.61 ms   | 105.15 ms   | 345.55 ms | 599.09 ms | 898.75 ms | 8            |
| v1/identity/map   | GET    | 6769 | 1.56 MB/s  | 49.71 ms    | 0.86 ms     | 38.52 ms  | 79.99 ms  | 264.23 ms | 300          |
| v1/token/refresh  | GET    | 2353 | 1.44 MB/s  | 135.05 ms   | 4.91 ms     | 113.01 ms | 217.02 ms | 489.30 ms | 300          |
| v1/token/generate | GET    | 2421 | 1.48 MB/s  | 126.57 ms   | 4.56 ms     | 111.04 ms | 213.12 ms | 524.17 ms | 300          |
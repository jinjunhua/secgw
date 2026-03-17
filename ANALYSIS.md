# secgw 项目代码分析报告

## 目录

1. [项目概述](#1-项目概述)
2. [设计思路与架构](#2-设计思路与架构)
3. [构建系统分析](#3-构建系统分析)
4. [密码核心层分析](#4-密码核心层分析)
   - 4.1 [SM3 哈希算法](#41-sm3-哈希算法)
   - 4.2 [SM4 分组密码](#42-sm4-分组密码)
   - 4.3 [SM2 椭圆曲线密码](#43-sm2-椭圆曲线密码)
5. [数据平面加速层分析](#5-数据平面加速层分析)
   - 5.1 [DPDK 集成层](#51-dpdk-集成层)
   - 5.2 [VPP 插件](#52-vpp-插件)
6. [控制平面层分析](#6-控制平面层分析)
   - 6.1 [IKEv2 协商头文件](#61-ikev2-协商头文件)
   - 6.2 [strongSwan 插件](#62-strongswan-插件)
7. [测试体系分析](#7-测试体系分析)
8. [配置文件分析](#8-配置文件分析)
9. [安全性评估](#9-安全性评估)
10. [总结](#10-总结)

---

## 1. 项目概述

**secgw**（Secure Gateway）是一个基于中国国家密码标准（**国密算法**）的 IPSec 安全网关实现。项目将 SM2、SM3、SM4 三个国密算法融合进 IPSec/IKEv2 协议栈，支持在 strongSwan（控制平面）和 VPP/DPDK（数据平面）环境中部署。

### 技术栈

| 层次 | 组件 | 技术 |
|------|------|------|
| 控制平面 | IKEv2 协商 | strongSwan 插件 |
| 数据平面 | ESP 封装/解封 | VPP 节点图 |
| 加速层 | 硬件卸载 | DPDK 加密 PMD |
| 密码核心 | 国密算法 | 纯 C 实现（无外部依赖） |

### 项目特点

- **零外部依赖**：密码核心完全自包含，不依赖 OpenSSL 等第三方库
- **可移植性**：标准 C11，适用于 Linux/嵌入式等多种平台
- **分层解耦**：密码层、集成层、配置层职责清晰分离
- **合规性**：严格遵循 GM/T 0002-2012、GM/T 0003-2012、GM/T 0004-2012 标准

---

## 2. 设计思路与架构

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────┐
│              应用/配置层                              │
│   ipsec.conf   strongswan.conf   vpp.conf            │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────┐
│              控制平面（IKEv2）                        │
│   strongSwan Plugin                                  │
│   ┌──────────────┬──────────────┬─────────────────┐  │
│   │ SM4 Crypter  │ SM3 Hasher   │ SM2 KE          │  │
│   │              │ HMAC-SM3 PRF │                 │  │
│   └──────────────┴──────────────┴─────────────────┘  │
│   gm_ike.h  (IKEv2 Transform IDs)                    │
└────────────────────┬────────────────────────────────┘
                     │ SA 参数下发
┌────────────────────┴────────────────────────────────┐
│              数据平面（ESP 封装）                     │
│   VPP Plugin                DPDK PMD                 │
│   gm-esp4-encrypt           gm_sw_process_cipher     │
│   gm-esp4-decrypt           gm_sw_process_aead       │
│                             gm_sw_process_auth        │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────┐
│              密码核心层（无依赖）                     │
│   sm3.c / sm3.h      SM3 哈希 + HMAC-SM3            │
│   sm4.c / sm4.h      SM4-ECB/CBC/CTR/GCM            │
│   sm2.c / sm2.h      SM2 签名/ECDH/加密             │
└─────────────────────────────────────────────────────┘
```

### 2.2 设计原则

**最小化依赖**：`sm2.c`、`sm3.c`、`sm4.c` 只依赖标准 C 库（`<string.h>`、`<stdlib.h>`），可直接移植到裸机或 RTOS 环境。

**上层隔离**：VPP 插件和 DPDK PMD 都通过调用 `sm4_gcm_encrypt`、`sm3_hmac` 等函数访问密码层，不直接操作内部状态。

**软件回退**：`dpdk_gm_crypto.c` 在没有 DPDK 硬件的情况下，通过 `gm_sw_process_*` 系列函数提供纯软件路径，保证测试和集成的连续性。

---

## 3. 构建系统分析

### 文件：`CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.16)
project(secgw C)
set(CMAKE_C_STANDARD 11)
```

项目使用 CMake 构建，标准设为 **C11**（利用了 `_Bool`、指定初始化等特性）。

#### 构建目标

| 目标 | 类型 | 说明 |
|------|------|------|
| `gm_crypto` | 静态库 | 核心密码库（sm2/sm3/sm4） |
| `gm_dpdk` | 静态库 | DPDK 集成层（含软件回退） |
| `test_sm3/sm4/sm2/ipsec` | 可执行文件 | 各模块独立测试 |
| `test_all` | 可执行文件 | 统一测试套件 |

#### 编译选项

```cmake
set(WARN_FLAGS "-Wall -Wextra -Wno-unused-parameter -Wno-sign-compare")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
```

Release 构建开启 `-O3` 优化，对密码运算（特别是 SM4 S-Box 查表、SM3 压缩函数）有显著加速效果。

#### 可选特性

| 选项 | 默认 | 说明 |
|------|------|------|
| `BUILD_TESTS` | ON | 编译测试程序 |
| `BUILD_VPP_PLUGIN` | OFF | 编译 VPP 插件（需要 VPP 开发头文件） |
| `WITH_DPDK` | OFF | 链接 DPDK 硬件 PMD（通过 pkg-config 查找） |

---

## 4. 密码核心层分析

### 4.1 SM3 哈希算法

#### 文件：`src/crypto/sm3.h` / `src/crypto/sm3.c`

SM3 是中国标准哈希算法（GM/T 0004-2012），输出 256 位摘要，结构与 SHA-256 类似但细节不同。

#### 数据结构

```c
typedef struct {
    uint32_t state[8];   // 8个32位状态字，初值为IV
    uint64_t count;      // 已处理字节总数（用于填充计算）
    uint8_t  buf[64];    // 未满一个块（64字节）的缓冲区
} sm3_ctx_t;
```

**状态机模式**：`sm3_init` → `sm3_update`（可多次调用）→ `sm3_final`，支持流式处理任意长度数据。

#### 初始向量

```c
static const uint32_t SM3_IV[8] = {
    0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u,
    0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu
};
```

SM3 的 IV 是标准规定的固定常量，与 SHA-256 不同。

#### 核心宏定义

```c
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define T(j)  (((j) < 16) ? 0x79cc4519u : 0x7a879d8au)
#define FF(x, y, z, j) (((j) < 16) ? ((x)^(y)^(z)) : (((x)&(y))|((x)&(z))|((y)&(z))))
#define GG(x, y, z, j) (((j) < 16) ? ((x)^(y)^(z)) : (((x)&(y))|(~(x)&(z))))
#define P0(x) ((x) ^ ROTL32((x),9)  ^ ROTL32((x),17))
#define P1(x) ((x) ^ ROTL32((x),15) ^ ROTL32((x),23))
```

- `T(j)`：轮常量，前16轮和后48轮取不同的值
- `FF`/`GG`：布尔函数，前16轮为异或，后48轮为多数/选择函数
- `P0`/`P1`：置换函数，P0 用于压缩函数输出，P1 用于消息扩展

#### 压缩函数 `sm3_compress`

```c
static void sm3_compress(uint32_t state[8], const uint8_t block[SM3_BLOCK_SIZE])
{
    uint32_t W[68], W1[64];
    // ...
    // 消息扩展：将 16 个字扩展为 68 个字 (W) 和 64 个字 (W')
    for (j = 0; j < 16; j++)
        W[j] = get_uint32_be(block, j * 4);   // 大端读入
    for (j = 16; j < 68; j++)
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL32(W[j-3], 15))
               ^ ROTL32(W[j-13], 7) ^ W[j-6];
    for (j = 0; j < 64; j++)
        W1[j] = W[j] ^ W[j + 4];              // W' = W ⊕ W_{j+4}

    // 64 轮压缩
    for (j = 0; j < 64; j++) {
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T(j), j % 32), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        // 状态更新：8 个工作寄存器循环移位
        D = C; C = ROTL32(B, 9); B = A; A = TT1;
        H = G; G = ROTL32(F, 19); F = E; E = P0(TT2);
    }
    // 链式异或（Merkle-Damgård 结构）
    state[0] ^= A; /* ... */
}
```

**消息扩展**将 64 字节（16 个字）扩展为 132 个字（W[0..67] + W'[0..63]），与 SHA-256 的消息调度算法相比引入了 P1 置换函数，使得扩展结果具有更强的雪崩效应。

#### 填充与最终处理

```c
void sm3_final(sm3_ctx_t *ctx, uint8_t digest[SM3_DIGEST_SIZE])
{
    uint64_t bits = ctx->count * 8;
    uint8_t pad = 0x80;

    sm3_update(ctx, &pad, 1);           // 附加 0x80
    pad = 0x00;
    while ((ctx->count % 64) != 56)     // 填充到 56 mod 64
        sm3_update(ctx, &pad, 1);
    sm3_update(ctx, msglen, 8);         // 附加 64 位大端比特长度

    for (int i = 0; i < 8; i++)
        put_uint32_be(digest, i * 4, ctx->state[i]);

    memset(ctx, 0, sizeof(*ctx));       // 清除敏感状态
}
```

填充方案与 SHA-256 完全一致（Merkle-Damgård 强化填充），末尾附加消息比特长度的大端编码。`memset(ctx, 0, ...)` 防止摘要值在内存中残留。

#### HMAC-SM3

```c
void sm3_hmac(const uint8_t *key, size_t key_len, ...)
{
    // 若 key 超过块长，先哈希压缩
    if (key_len > SM3_BLOCK_SIZE) { sm3(key, key_len, tk); ... }

    // 内层哈希：SM3(K ⊕ ipad || data)
    sm3_init(&ctx);
    sm3_update(&ctx, k_ipad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, data, data_len);
    sm3_final(&ctx, inner);

    // 外层哈希：SM3(K ⊕ opad || inner)
    sm3_init(&ctx);
    sm3_update(&ctx, k_opad, SM3_BLOCK_SIZE);
    sm3_update(&ctx, inner, SM3_DIGEST_SIZE);
    sm3_final(&ctx, mac);

    memset(k_ipad, 0, sizeof(k_ipad));  // 清除密钥材料
    memset(k_opad, 0, sizeof(k_opad));
}
```

严格遵循 RFC 2104 的 HMAC 构造，ipad = 0x36，opad = 0x5C。用于 IPSec ESP 数据完整性保护和 IKEv2 的 PRF 函数。

---

### 4.2 SM4 分组密码

#### 文件：`src/crypto/sm4.h` / `src/crypto/sm4.c`

SM4 是中国标准对称分组密码（GM/T 0002-2012），块长 128 位，密钥长 128 位，32 轮 Feistel 结构。

#### 数据结构

```c
typedef struct {
    uint32_t rk[32]; // 32 个轮密钥，每个 32 位
} sm4_ctx_t;
```

轮密钥在 `sm4_set_key_enc` 或 `sm4_set_key_dec` 时预计算并存储，之后加密/解密只需查表。

#### S-Box

```c
static const uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, ... // 256 字节非线性替换表
};
```

SM4 的 S-Box 是一个 8-bit → 8-bit 的非线性置换，基于有限域 GF(2⁸) 的逆元计算，是算法抵抗差分和线性分析的核心组件。

#### 密钥扩展

```c
void sm4_set_key_enc(sm4_ctx_t *ctx, const uint8_t key[SM4_KEY_SIZE])
{
    uint32_t K[4], tmp;
    // 初始化：K[i] = key[i] ⊕ FK[i]（系统参数）
    K[0] = get_u32_be(key + 0) ^ FK[0];
    // ...
    for (int i = 0; i < 32; i++) {
        tmp = K[1] ^ K[2] ^ K[3] ^ CK[i];   // CK 为密钥常量
        ctx->rk[i] = K[0] ^ sm4_T_prime(tmp); // T' = L'(τ(·))
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = ctx->rk[i];
    }
}
```

- **FK**：4 个 32 位系统参数，固定常量
- **CK**：32 个 32 位密钥常量，由索引编码生成
- **T' 变换**：使用 S-Box（τ）和修改的线性变换 L'（相比加密用的 L，旋转量不同）

解密密钥只需将加密轮密钥倒序排列：
```c
void sm4_set_key_dec(sm4_ctx_t *ctx, const uint8_t key[SM4_KEY_SIZE])
{
    sm4_ctx_t enc;
    sm4_set_key_enc(&enc, key);
    for (int i = 0; i < 32; i++)
        ctx->rk[i] = enc.rk[31 - i];  // 逆序即解密
}
```

#### 轮函数与加密主体

```c
static void sm4_one_round(const uint32_t rk[32],
                           const uint8_t in[16], uint8_t out[16])
{
    uint32_t X[36];
    X[0..3] = get_u32_be(in + i*4);   // 输入分为 4 个 32 位字

    for (int i = 0; i < 32; i++)
        X[i+4] = X[i] ^ sm4_T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i]);
    // X[i+4] = X[i] ⊕ T(X[i+1] ⊕ X[i+2] ⊕ X[i+3] ⊕ rk[i])

    // 输出逆序（SM4 特有的反序变换 R）
    put_u32_be(out + 0,  X[35]);
    put_u32_be(out + 4,  X[34]);
    put_u32_be(out + 8,  X[33]);
    put_u32_be(out + 12, X[32]);
}
```

**T 变换** = τ（S-Box 逐字节替换） + L（线性变换）：
```c
static inline uint32_t sm4_L(uint32_t b) {
    return b ^ rotl32(b,2) ^ rotl32(b,10) ^ rotl32(b,18) ^ rotl32(b,24);
}
static inline uint32_t sm4_T(uint32_t a) { return sm4_L(sm4_tau(a)); }
```

输出的"反序变换" `R(A₀, A₁, A₂, A₃) = (A₃, A₂, A₁, A₀)` 让加解密共享同一个 `sm4_one_round` 函数，只需用不同方向的轮密钥即可。

#### CBC 模式

```c
void sm4_cbc_encrypt(const sm4_ctx_t *ctx, const uint8_t *iv,
                     const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t tmp[16];
    memcpy(tmp, iv, 16);   // IV 复制到临时变量（不修改原始 IV）
    while (len >= 16) {
        for (int i = 0; i < 16; i++) tmp[i] ^= in[i]; // C_i = E(P_i ⊕ C_{i-1})
        sm4_encrypt(ctx, tmp, out);
        memcpy(tmp, out, 16);  // 当前密文作为下一块 IV
        in += 16; out += 16; len -= 16;
    }
}
```

解密时使用 `sm4_set_key_dec` 生成的反向轮密钥，但 CBC 解密中需要保存前一密文块作异或：

```c
void sm4_cbc_decrypt(...) {
    memcpy(prev, iv, 16);
    while (len >= 16) {
        sm4_decrypt(ctx, in, tmp);
        for (int i = 0; i < 16; i++) out[i] = tmp[i] ^ prev[i]; // P_i = D(C_i) ⊕ C_{i-1}
        memcpy(prev, in, 16);  // 保存当前密文供下一块使用
        ...
    }
}
```

#### CTR 模式

```c
void sm4_ctr_crypt(const sm4_ctx_t *ctx, uint8_t *ctr,
                   const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t ks[16];
    while (len >= 16) {
        sm4_encrypt(ctx, ctr, ks);  // 密钥流 = E(CTR)
        sm4_ctr_inc(ctr);           // CTR 自增（从低位进位）
        for (i = 0; i < 16; i++) out[i] = in[i] ^ ks[i]; // XOR 加密
        ...
    }
    // 处理最后不满一块的数据
    if (len > 0) { sm4_encrypt(ctx, ctr, ks); ... }
    memset(ks, 0, sizeof(ks));  // 清除密钥流
}
```

CTR 模式加解密操作完全对称，只需加密方向即可，因此统一使用 `sm4_encrypt`。

#### GCM 模式

GCM 模式是 SM4 中最复杂的部分，结合了 CTR 加密和 GHASH 认证：

**GCM 核心数据结构：**
```c
typedef struct { uint64_t hi, lo; } u128_t;  // 128 位 GF(2^128) 元素
```

**GHASH 乘法（GF(2¹²⁸) 上的多项式乘法）：**
```c
static void ghash_mul(u128_t *x, const u128_t *h)
{
    u128_t z = {0, 0}, v = *h;
    // 逐位处理：128 次迭代
    for (int i = 0; i < 128; i++) {
        bit = (i < 64) ? (xi_hi >> (63-i)) & 1 : (xi_lo >> (127-i)) & 1;
        if (bit) { z.hi ^= v.hi; z.lo ^= v.lo; }
        // v = v / x（在 GF(2^128) 中右移，若溢出则 XOR 多项式系数）
        uint64_t carry = v.lo & 1;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi >>= 1;
        if (carry) v.hi ^= (uint64_t)0xe1 << 56; // x^128 + x^7 + x^2 + x + 1
    }
    *x = z;
}
```

GHASH 使用 GF(2¹²⁸) 上的不可约多项式 `x¹²⁸ + x⁷ + x² + x + 1`（NIST GCM 规范），多项式系数 0xe1 对应高位字节的 `x⁷ + x⁶ + x⁵`。

**GCM 加密流程：**
```
H = E_K(0^128)            ← 加密全零块得到 GHASH 密钥
J0 = IV || 0x00000001     ← 对 96 位 IV 直接拼接计数器 1
ctr = J0 + 1              ← 加密从计数器 2 开始
C = CTR_E(K, ctr, P)      ← CTR 模式加密明文
T = GHASH(H, A, C) ⊕ E_K(J0)  ← 计算认证标签
```

**GCM 解密时先验证后解密**（Decrypt-then-Verify 的变体，实际是先计算标签再解密）：
```c
// 先计算期望标签
ghash(&h_val, aad, aad_len, in, in_len, J0, full_tag);
for (size_t i = 0; i < 16; i++) full_tag[i] ^= ej0[i];

// 常量时间比较
uint8_t diff = 0;
for (size_t i = 0; i < tag_len; i++) diff |= full_tag[i] ^ tag[i];
if (diff != 0) { ...; return -1; }  // 验证失败立即返回

// 验证通过后才解密
sm4_ctr_crypt(&ctx, ctr, in, out, in_len);
```

常量时间比较（`diff |= a ^ b`）防止时序侧信道攻击。

---

### 4.3 SM2 椭圆曲线密码

#### 文件：`src/crypto/sm2.h` / `src/crypto/sm2.c`

SM2 是中国标准公钥密码（GM/T 0003-2012），基于 256 位素域椭圆曲线，提供数字签名、密钥封装和 ECDH 密钥交换三种功能。

#### 曲线参数

SM2 推荐曲线（256 位素数域）参数：

| 参数 | 值（简写） | 说明 |
|------|----------|------|
| p | `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF` | 素数模数 |
| a | `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC` | 曲线系数 a |
| b | `28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93` | 曲线系数 b |
| n | `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123` | 基点阶 |
| Gx | `32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7` | 基点 x 坐标 |
| Gy | `BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0` | 基点 y 坐标 |

曲线方程：y² = x³ + ax + b（over GF(p)）

#### 大整数实现

SM2 的所有运算基于一个简单的 256 位大整数库，用 8 个 32 位字（大端序）表示：

```c
#define BN_LIMBS 8
typedef uint32_t bn256_t[BN_LIMBS];  // [0] = 最高位 ... [7] = 最低位
```

**关键运算：**

```c
// 模加：r = (a + b) mod m，处理进位溢出
static void bn_add_mod(bn256_t r, const bn256_t a, const bn256_t b, const bn256_t m)
{
    uint64_t carry = 0;
    for (int i = BN_LIMBS-1; i >= 0; i--) {
        uint64_t s = (uint64_t)a[i] + b[i] + carry;
        r[i] = (uint32_t)s;
        carry = s >> 32;
    }
    if (carry) {
        // a+b 超过 256 位，结果 = r + (2^256 - m) = r + ~m + 1
        uint64_t c2 = 1;
        for (int i = BN_LIMBS-1; i >= 0; i--) {
            uint64_t s = (uint64_t)r[i] + (uint32_t)~m[i] + c2;
            r[i] = (uint32_t)s; c2 = s >> 32;
        }
    } else if (bn_cmp(r, m) >= 0) {
        bn_sub(r, r, m);
    }
}
```

**模乘（二进制倍加）：**
```c
static void bn_mul_mod(bn256_t r, const bn256_t a, const bn256_t b, const bn256_t m)
{
    bn256_t result = {0}, temp = a, b_copy = b;
    while (!bn_is_zero(b_copy)) {
        if (b_copy[BN_LIMBS-1] & 1u)     // b 的最低位为 1
            bn_add_mod(result, result, temp, m); // result += temp
        bn_add_mod(temp, temp, temp, m);  // temp *= 2
        // b_copy >>= 1（大端右移）
        for (int i = BN_LIMBS-1; i > 0; i--)
            b_copy[i] = (b_copy[i] >> 1) | (b_copy[i-1] << 31);
        b_copy[0] >>= 1;
    }
    bn_copy(r, result);
}
```

时间复杂度：O(256) 次模加，每次 O(8) 次 64 位运算，共约 2048 次 64 位加法。对比 Montgomery 乘法，性能较低但实现简单易验证。

**模逆（费马小定理）：**
```c
static void bn_inv_mod(bn256_t r, const bn256_t a, const bn256_t m)
{
    // r = a^(m-2) mod m（当 m 为素数时等于 a^(-1) mod m）
    bn256_t exp = m - 2;  // exp = m - 2
    // 快速幂：square-and-multiply
    while (!bn_is_zero(exp)) {
        if (exp[BN_LIMBS-1] & 1u) bn_mul_mod(result, result, base, m);
        bn_mul_mod(base, base, base, m);
        exp >>= 1;
    }
}
```

SM2 的素数域和基点阶都是素数，满足费马小定理条件，因此模逆通过 a^(m-2) mod m 计算。

#### 椭圆曲线点运算

```c
typedef struct { bn256_t x, y; int infinity; } ec_point_t;
```

**点加法（仿射坐标）：**
```c
static void ec_point_add(ec_point_t *r, const ec_point_t *p, const ec_point_t *q)
{
    if (p->infinity) { *r = *q; return; }  // P + O = P
    if (q->infinity) { *r = *p; return; }

    if (bn_cmp(p->x, q->x) == 0 && bn_cmp(p->y, q->y) != 0) {
        r->infinity = 1; return;            // P + (-P) = O
    }

    if (/* p == q */) {
        // 倍点公式：λ = (3x² + a) / (2y)
        bn_mul_mod(x2, p->x, p->x, g_p);       // x²
        bn_add_mod(three_x2, x2+x2, x2, g_p);  // 3x²
        bn_add_mod(three_x2, three_x2, g_a, g_p); // 3x²+a
        bn_add_mod(two_y, p->y, p->y, g_p);    // 2y
        bn_inv_mod(lam, two_y, g_p);            // (2y)^(-1)
        bn_mul_mod(lam, three_x2, lam, g_p);   // λ
    } else {
        // 普通点加公式：λ = (y_Q - y_P) / (x_Q - x_P)
        bn_sub_mod(dy, q->y, p->y, g_p);
        bn_sub_mod(dx, q->x, p->x, g_p);
        bn_inv_mod(lam, dx, g_p);
        bn_mul_mod(lam, dy, lam, g_p);
    }
    // x_R = λ² - x_P - x_Q mod p
    bn_mul_mod(lam2, lam, lam, g_p);
    bn_sub_mod(r->x, lam2, p->x, g_p);
    bn_sub_mod(r->x, r->x, q->x, g_p);
    // y_R = λ(x_P - x_R) - y_P mod p
    bn_sub_mod(t1, p->x, r->x, g_p);
    bn_mul_mod(r->y, lam, t1, g_p);
    bn_sub_mod(r->y, r->y, p->y, g_p);
}
```

**标量乘法（从高位到低位的双倍加法）：**
```c
static void ec_scalar_mul(ec_point_t *r, const ec_point_t *p, const bn256_t k)
{
    ec_point_t result = {.infinity = 1};  // 初始为无穷远点
    for (int i = 0; i < BN_LIMBS; i++) {
        for (int bit = 31; bit >= 0; bit--) {
            ec_point_add(&doubled, &result, &result); // 每步倍点
            result = doubled;
            if ((k[i] >> bit) & 1u) {
                ec_point_add(&added, &result, p);     // k 当前位为 1 则加 p
                result = added;
            }
        }
    }
    *r = result;
}
```

256 位标量乘法共执行 256 次倍点和最多 256 次点加，每次点加/倍点需要 2 次模逆（代价较高），每次模逆需要约 256 次模乘。整体性能约 O(256³) 次 64 位运算，适合正确性演示，生产环境宜替换为 Montgomery 梯形或固定窗口算法。

#### SM2 签名

```c
int sm2_sign(const sm2_key_t *key, const uint8_t *id, size_t id_len,
             const uint8_t *msg, size_t msg_len, sm2_sig_t *sig, ...)
{
    // 1. 计算用户标识 Z = SM3(ENTL || ID || a || b || Gx || Gy || Qx || Qy)
    sm2_compute_z(id, id_len, key->Qx, key->Qy, Z);

    // 2. 计算消息摘要 e = SM3(Z || M)
    sm3_update(&hctx, Z, 32);
    sm3_update(&hctx, msg, msg_len);
    sm3_final(&hctx, e_bytes);

    do {
        // 3. 生成随机数 k ∈ [1, n-1]
        rng(k_bytes, 32, rng_ctx);

        // 4. 计算 (x1, y1) = k*G
        ec_scalar_mul(&P1, &g_G, k);

        // 5. r = (e + x1) mod n，若 r=0 或 r+k=n 则重试
        bn_add_mod(r, e, x1_modn, g_n);
    } while (bn_is_zero(r) || bn_is_zero(r+k));

    // 6. s = ((1+d)^(-1) * (k - r*d)) mod n
    bn_add_mod(tmp1, one, d, g_n);  // 1+d
    bn_inv_mod(tmp2, tmp1, g_n);    // (1+d)^(-1)
    bn_mul_mod(rd, r, d, g_n);      // r*d
    bn_sub_mod(tmp1, k, rd, g_n);   // k - r*d
    bn_mul_mod(s, tmp2, tmp1, g_n); // s
}
```

SM2 签名公式 `s = (1+d)^(-1) * (k - r*d) mod n` 与 ECDSA 的 `s = k^(-1) * (e + r*d) mod n` 不同，SM2 的签名方程设计使得即使已知 (r, s) 也更难推断私钥 d。

#### SM2 公钥加密

加密格式：`C = 04 || C1x || C1y || C3 || C2`

- **C1**（65 字节）：随机点 `k*G`（前缀 `04` 表示未压缩格式）
- **C3**（32 字节）：`SM3(x2 || M || y2)`（完整性校验）
- **C2**（可变）：`M ⊕ KDF(x2, y2)`（加密密文）

```c
// KDF：基于 SM3 的密钥派生
uint32_t ct_kdf = 1;
while (done < plain_len) {
    sm3_update(&hctx, x2, 32);           // 共享密钥 x 坐标
    sm3_update(&hctx, y2, 32);           // 共享密钥 y 坐标
    sm3_update(&hctx, ct_bytes, 4);      // 计数器（大端）
    sm3_final(&hctx, ha);                // 哈希输出用作密钥流
    for (size_t i = 0; i < chunk; i++)
        t[done+i] = plain[done+i] ^ ha[i]; // XOR 加密
    ct_kdf++;
}
```

#### ECDH 密钥交换

```c
int sm2_ecdh(const sm2_key_t *local_key,
             const uint8_t *peer_Qx, const uint8_t *peer_Qy,
             uint8_t shared[SM2_SHARED_KEY_SIZE])
{
    ec_scalar_mul(&result, &peer_Q, d);  // shared = d * Q_peer
    if (result.infinity) return -1;
    bn_to_bytes(shared, result.x);       // 取 x 坐标作为共享秘密
    memset(&d, 0, sizeof(d));            // 清除私钥
    return 0;
}
```

返回共享点的 x 坐标（32 字节），可进一步通过 KDF 派生对称密钥（在 IKEv2 中由 `PRF+` 完成）。

---

## 5. 数据平面加速层分析

### 5.1 DPDK 集成层

#### 文件：`src/dpdk/dpdk_gm_crypto.h` / `dpdk_gm_crypto.c`

DPDK 层提供两套接口：纯软件路径（无 DPDK 依赖）和硬件 PMD 路径（`HAVE_DPDK` 宏）。

#### 会话结构

```c
typedef struct {
    uint8_t key[16]; uint8_t iv[16];
    int encrypt;      // 1=加密, 0=解密
} gm_sm4_cbc_session_t;

typedef struct {
    uint8_t key[16]; uint8_t iv[12];
    size_t aad_len; size_t tag_len;
    int encrypt;
} gm_sm4_gcm_session_t;

typedef struct {
    uint8_t key[64]; size_t key_len;
} gm_hmac_sm3_session_t;
```

会话结构将密钥材料和操作参数封装在一起，类似 DPDK 的 `rte_cryptodev_sym_session`，便于批量处理。

#### 软件路径

```c
int gm_sw_process_cipher(const gm_sm4_cbc_session_t *sess,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    if (len % SM4_BLOCK_SIZE != 0) return -1;   // CBC 需要对齐
    sm4_ctx_t ctx;
    if (sess->encrypt) {
        sm4_set_key_enc(&ctx, sess->key);
        sm4_cbc_encrypt(&ctx, sess->iv, in, out, len);
    } else {
        sm4_set_key_dec(&ctx, sess->key);
        sm4_cbc_decrypt(&ctx, sess->iv, in, out, len);
    }
    memset(&ctx, 0, sizeof(ctx));   // 清除轮密钥
    return 0;
}
```

软件路径直接调用 `gm_crypto` 库，并在完成后清除敏感的轮密钥材料。

#### DPDK PMD 注册（硬件路径）

```c
static const struct rte_cryptodev_capabilities gm_pmd_capabilities[] = {
    {   // SM4-CBC 复用 AES-CBC 的 DPDK 枚举槽位
        .op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
        .sym.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
        .sym.cipher = {
            .algo = RTE_CRYPTO_CIPHER_AES_CBC,  // 注意：复用现有枚举
            .block_size = 16,
            .key_size = { .min = 16, .max = 16, .increment = 0 },
            .iv_size  = { .min = 16, .max = 16, .increment = 0 }
        }
    },
    RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};
```

由于 DPDK 尚未有官方的 SM4 枚举（国密算法支持在 DPDK 社区仍在推进中），此处通过复用 AES-CBC 的枚举槽位作为过渡方案，配合自定义 ID 宏 `GM_CIPHER_SM4_CBC = 0x1001` 等区分。

---

### 5.2 VPP 插件

#### 文件：`src/vpp/gm_ipsec_plugin/gm_ipsec.h` / `gm_ipsec.c`

VPP（Vector Packet Processing）是一个用于高性能网络功能的数据平面框架。本插件为 VPP 添加了 SM4-GCM 的 ESP 加密/解密节点。

#### ESP 数据包格式

```
 ┌────────────────────────────────────────────────────┐
 │ SPI (4B) │ SEQ (4B) │ IV (12B) │ 密文 │ ICV (16B) │
 └────────────────────────────────────────────────────┘
   ← ESP 头部 (8B) →│← GCM IV →│← 有效载荷 →│← 标签 →
```

GCM IV 构造：`iv = iv_base XOR (seq 放在最后 4 字节)`，保证每个报文使用唯一的 IV，同时允许从 SA 的基础 IV 计算（避免同步问题）。

#### SA 数据库

```c
typedef struct {
    uint8_t  enc_key[16];   // SM4 加密密钥
    uint8_t  auth_key[32];  // HMAC-SM3 认证密钥（AEAD 模式下不用）
    uint32_t spi;           // SA 唯一标识
    uint32_t seq;           // 序列号（自增防重放）
    uint8_t  iv[12];        // GCM IV 基值
} gm_sa_ctx_t;

typedef struct {
    u32 enc_node_index, dec_node_index;
    gm_sa_ctx_t *sa_pool;   // VPP 向量池（vec_validate）
    ...
} gm_ipsec_main_t;
```

#### 加密节点

```c
static uword gm_esp4_encrypt_fn(vlib_main_t *vm,
                                  vlib_node_runtime_t *node,
                                  vlib_frame_t *frame)
{
    // VPP 标准的批处理循环结构
    while (n_left_from > 0) {
        vlib_get_next_frame(...);
        while (n_left_from > 0 && n_left_to_next > 0) {
            // 1. 从 buffer 的 opaque 字段获取 SA 索引
            u32 sa_idx = vnet_buffer(b)->ipsec.sad_index;

            // 2. 腾出 ESP 头部空间
            vlib_buffer_advance(b, -(i32)(ESP_HDR_SIZE + ESP_IV_SIZE));
            esp->spi = clib_host_to_net_u32(sa->spi);
            esp->seq = clib_host_to_net_u32(++sa->seq);

            // 3. 构造唯一 GCM IV
            memcpy(iv, sa->iv, 12);
            *iv_seq ^= clib_host_to_net_u32(sa->seq);  // XOR 序列号

            // 4. AAD = SPI || SEQ（8 字节，已写入 ESP 头部）
            memcpy(aad, esp, 8);

            // 5. SM4-GCM 加密
            sm4_gcm_encrypt(sa->enc_key, iv, 12, aad, 8,
                            payload, payload_len, enc_out, tag, 16);

            // 6. 追加 ICV
            memcpy(icv, tag, 16);
            b->current_length = ESP_HDR_SIZE + ESP_IV_SIZE + payload_len + 16;
        }
        vlib_put_next_frame(...);
    }
}
```

VPP 节点图中，数据包以向量（批次）形式处理，最大化 CPU 缓存利用率。`VLIB_REGISTER_NODE` 宏将节点注册到 VPP 的图中：

```c
VLIB_REGISTER_NODE(gm_esp4_encrypt_node) = {
    .function   = gm_esp4_encrypt_fn,
    .name       = "gm-esp4-encrypt",
    .n_next_nodes = GM_ESP_ENC_N_NEXT,
    .next_nodes = {
        [GM_ESP_ENC_NEXT_INTERFACE_OUTPUT] = "interface-output",
        [GM_ESP_ENC_NEXT_DROP]             = "error-drop",
    },
};
```

`VLIB_INIT_FUNCTION(gm_ipsec_init)` 在 VPP 启动时自动调用，初始化 SA 池并注册节点。

---

## 6. 控制平面层分析

### 6.1 IKEv2 协商头文件

#### 文件：`src/ike/gm_ike.h`

定义了 GM 算法在 IKEv2 中使用的变换 ID：

```c
// IKEv2 变换类型 1（加密算法）
#define IKEV2_ENCR_SM4_CBC      28  // RFC 8709 / IANA 待分配
#define IKEV2_ENCR_SM4_CTR      29
#define IKEV2_ENCR_SM4_GCM_16   30  // 16 字节 ICV

// 变换类型 3（完整性算法）
#define IKEV2_AUTH_HMAC_SM3_256 31

// 变换类型 2（PRF）
#define IKEV2_PRF_HMAC_SM3      32

// 变换类型 4（DH 组）
#define IKEV2_DH_SM2_256        41
```

> ⚠️ **注意**：上述变换 ID（28-32、41）为本项目占位值，IANA 尚未为国密算法分配正式编号。在互操作生产部署中，应使用 IANA 私有范围（IKEv2 私有加密算法 ID 范围：65001-65535）或等待 IANA 正式分配，以避免与未来标准分配冲突。

预定义的协商提案：

```c
// IKE SA 提案
static const gm_ike_proposal_t GM_IKE_PROPOSAL = {
    .encr_id     = IKEV2_ENCR_SM4_CBC,   // 加密：SM4-CBC-128
    .encr_keylen = 128,
    .integ_id    = IKEV2_AUTH_HMAC_SM3_256, // 完整性：HMAC-SM3
    .prf_id      = IKEV2_PRF_HMAC_SM3,   // PRF：HMAC-SM3
    .dh_id       = IKEV2_DH_SM2_256,     // 密钥交换：SM2-256
};

// ESP SA 提案（AEAD 模式，无单独完整性算法）
static const gm_esp_proposal_t GM_ESP_PROPOSAL_AEAD = {
    .encr_id     = IKEV2_ENCR_SM4_GCM_16, // SM4-GCM（自带认证）
    .encr_keylen = 128,
    .integ_id    = 0,                      // AEAD 不需要独立完整性
};
```

此头文件作为控制平面与数据平面之间的协议语义桥梁，统一了算法 ID 的命名空间。

### 6.2 strongSwan 插件

strongSwan 插件采用其标准的**插件特性机制**，通过 `PLUGIN_REGISTER` + `PLUGIN_PROVIDE` 宏声明能力。

#### 插件主体：`gm_plugin.c`

```c
METHOD(plugin_t, get_features, int,
    private_gm_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        PLUGIN_REGISTER(CRYPTER, gm_sm4_crypter_create),
            PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CBC, 16),    // SM4-CBC
        PLUGIN_REGISTER(CRYPTER, gm_sm4_crypter_create),
            PLUGIN_PROVIDE(CRYPTER, ENCR_SM4_CTR, 16),    // SM4-CTR
        PLUGIN_REGISTER(HASHER, gm_sm3_hasher_create),
            PLUGIN_PROVIDE(HASHER, HASH_SM3),              // SM3
        PLUGIN_REGISTER(PRF, gm_hmac_sm3_prf_create),
            PLUGIN_PROVIDE(PRF, PRF_HMAC_SM3),             // PRF-HMAC-SM3
        PLUGIN_REGISTER(SIGNER, gm_hmac_sm3_signer_create),
            PLUGIN_PROVIDE(SIGNER, AUTH_HMAC_SM3_256_256), // 完整性
        PLUGIN_REGISTER(KE, gm_sm2_ke_create),
            PLUGIN_PROVIDE(KE, SM2_256),                   // DH（SM2 ECDH）
    };
    *features = f;
    return countof(f);
}
```

每个 `PLUGIN_REGISTER` + `PLUGIN_PROVIDE` 对告诉 strongSwan 的插件管理器：**当需要某种算法时，调用对应的工厂函数**。

#### SM4 Crypter（`gm_sm4_crypter.c`）

```c
// strongSwan 密码器接口实现
struct private_sm4_crypter_t {
    crypter_t    public;   // strongSwan 密码器公共接口
    sm4_ctx_t    ctx_enc;  // 加密轮密钥
    sm4_ctx_t    ctx_dec;  // 解密轮密钥
    encryption_algorithm_t algo;
};

METHOD(crypter_t, encrypt, bool, ...)
{
    if (this->algo == ENCR_SM4_CBC) {
        sm4_cbc_encrypt(&this->ctx_enc, iv.ptr, data.ptr, out, data.len);
    } else if (this->algo == ENCR_SM4_CTR) {
        uint8_t ctr[16]; memcpy(ctr, iv.ptr, 16);
        sm4_ctr_crypt(&this->ctx_enc, ctr, data.ptr, out, data.len);
    }
}

METHOD(crypter_t, set_key, bool, ...)
{
    sm4_set_key_enc(&this->ctx_enc, key.ptr);
    sm4_set_key_dec(&this->ctx_dec, key.ptr);
    return TRUE;
}

METHOD(crypter_t, destroy_crypter, void, ...)
{
    memset(this, 0, sizeof(*this));  // 清零轮密钥
    free(this);
}
```

`set_key` 同时计算加密和解密轮密钥，这样 `decrypt` 操作无需重新计算。`destroy` 时清零整个结构体防止密钥泄漏。

#### SM3 Hasher（`gm_sm3_hasher.c`）

```c
METHOD(hasher_t, get_hash, bool,
    private_sm3_hasher_t *this, chunk_t chunk, uint8_t *hash)
{
    sm3_update(&this->ctx, chunk.ptr, chunk.len);
    if (hash) {
        sm3_ctx_t tmp = this->ctx;  // 复制状态，不影响继续更新
        sm3_final(&tmp, hash);
    }
    return TRUE;
}
```

巧妙地用 `sm3_ctx_t tmp = this->ctx` 复制状态，允许在不终止哈希上下文的情况下获取中间摘要，符合 strongSwan hasher 接口的语义。

#### SM2 KE（`gm_sm2_ke.c`）

```c
// 使用 /dev/urandom 作为 CSPRNG
static int urandom_rng(uint8_t *buf, size_t len, void *ctx) {
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t r = read(fd, buf, len); close(fd);
    return (r == (ssize_t)len) ? 0 : -1;
}

METHOD(key_exchange_t, get_public_key, bool, ...)
{
    // 格式：04 || Qx || Qy（65 字节，未压缩）
    value->ptr[0] = 0x04;
    memcpy(value->ptr + 1,  this->local_key.Qx, 32);
    memcpy(value->ptr + 33, this->local_key.Qy, 32);
}

METHOD(key_exchange_t, set_public_key, bool, ...)
{
    // 收到对端公钥后立即计算共享秘密
    sm2_ecdh(&this->local_key, peer_Qx, peer_Qy, this->shared);
}
```

#### HMAC-SM3 PRF/Signer（`gm_hmac_sm3_prf.c`）

```c
// Signer 的常量时间验证
METHOD(signer_t, verify_signature, bool, ...)
{
    sm3_hmac(this->key, this->key_len, data.ptr, data.len, mac);
    uint8_t diff = 0;
    for (size_t i = 0; i < this->trunc_len; i++)
        diff |= mac[i] ^ sig.ptr[i];  // 常量时间比较
    return diff == 0;
}
```

与 SM4-GCM 标签验证一样，使用 OR 累积差异的方式实现常量时间比较，防止时序侧信道攻击。

---

## 7. 测试体系分析

### 测试结构

项目包含 4 个独立测试模块，共 22 个测试用例：

| 测试文件 | 测试数量 | 覆盖内容 |
|----------|---------|---------|
| `test_sm3.c` | 6 | SM3 标准向量、HMAC、增量更新、大消息 |
| `test_sm4.c` | 8 | ECB 标准向量、CBC、CTR、GCM、全零测试 |
| `test_sm2.c` | 10 | 密钥生成、签名验签、Z 值、加解密、ECDH |
| `test_ipsec.c` | 10 | ESP 封装、篡改检测、SPI 验证、多包序列、DPDK 软件路径 |

### 测试框架

每个测试文件包含简单的宏定义测试框架：

```c
static int test_count = 0, test_passed = 0;
static void check(const char *name, int ok) {
    test_count++;
    if (ok) { test_passed++; printf("[PASS] %s\n", name); }
    else     { printf("[FAIL] %s\n", name); }
}
```

支持两种编译模式：
- **独立模式**（`#ifndef ALL_TESTS`）：直接提供 `main()`，编译为独立可执行文件
- **聚合模式**（`#define ALL_TESTS`）：导出 `run_xxx_tests()` 函数，由 `test_main.c` 统一调用

### 关键测试用例分析

#### SM3 标准向量验证

```c
const char *msg = "abc";
const uint8_t expected[32] = {
    0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9, ...
};
sm3((const uint8_t *)msg, 3, digest);
check("SM3(\"abc\") == expected", memcmp(digest, expected, 32) == 0);
```

使用 GM/T 0004-2012 标准附录中的测试向量，确保实现的正确性。

#### ESP 篡改检测

```c
esp_encap(&sa, payload, sizeof(payload)-1, esp_buf, &esp_len);
esp_buf[ESP_HDR_SIZE + ESP_IV_SIZE + 5] ^= 0x42;  // 翻转密文中的一个字节
r = esp_decap(&sa, esp_buf, esp_len, dec_buf, &dec_len);
check("ESP tampered packet rejected", r != 0);  // 必须被 GCM 认证拒绝
```

验证 SM4-GCM 的完整性保护有效，任何密文修改都会导致认证失败。

#### SM2 ECDH 对称性

```c
sm2_ecdh(&alice, bob.Qx, bob.Qy, shared_a);  // Alice 计算 d_A * Q_B
sm2_ecdh(&bob, alice.Qx, alice.Qy, shared_b); // Bob 计算 d_B * Q_A
check("SM2 ECDH shared secrets match",
      memcmp(shared_a, shared_b, 32) == 0);    // d_A*d_B*G 的 x 坐标应相等
```

验证 ECDH 的数学性质：`d_A * (d_B * G) = d_B * (d_A * G)`。

---

## 8. 配置文件分析

### `conf/ipsec.conf`（strongSwan 隧道配置）

```
conn gm-ipsec-tunnel
    keyexchange = ikev2
    ike = sm4cbc128-sha256-prfsha256-modp2048!
    esp = sm4gcm128-sm4gcm128!
```

- `ike` 字段配置 IKE SA 使用的算法套件（加密-完整性-PRF-DH）
- `!` 后缀表示只接受该套件（严格模式）
- `esp` 字段配置 ESP SA，`sm4gcm128` 表示 SM4-GCM-128（AEAD）
- ⚠️ **说明**：上述示例中 `sha256`、`prfsha256` 是 strongSwan 原生支持的默认算法名称，用于在未安装 GM 插件时也可测试 SM4-CBC 加密。当 GM 插件（`gm_plugin.so`）正确加载后，应替换为 `hmacSm3256-prfHmacSm3-sm2p256` 以全面使用国密算法：

```
# 完整国密套件（需 GM 插件已加载）
ike = sm4cbc128-hmacSm3256-prfHmacSm3-sm2p256!
esp = sm4gcm128!
```

### `conf/vpp.conf`（VPP 数据平面配置）

```
dpdk {
    dev 0000:00:08.0 { num-rx-queues 4 num-tx-queues 4 }
    dev crypto_scheduler { workers 0 }
}
plugins {
    plugin gm_ipsec_plugin.so { enable }
}
```

配置 DPDK 网卡绑定（需要先用 `dpdk-devbind.py` 将 NIC 绑定到 DPDK 驱动），并启用 GM IPSec 插件。

### `conf/strongswan.conf`（strongSwan 守护进程配置）

```
charon {
    plugins {
        gm { load = yes }
    }
    syslog {
        ike = 2    # IKE 日志级别
        esp = 2    # ESP 日志级别
    }
}
```

日志级别 2 对调试 IKE 协商很有帮助。

---

## 9. 安全性评估

### 优势

| 方面 | 评估 |
|------|------|
| SM4-GCM 认证 | ✅ 常量时间标签比较，防时序侧信道 |
| HMAC-SM3 验证 | ✅ 常量时间比较，防时序侧信道 |
| 密钥材料清零 | ✅ 所有关键路径使用 `memset` 清零 |
| SM3 完整实现 | ✅ 标准填充、正确的消息扩展 |
| SM4 模式完整 | ✅ ECB/CBC/CTR/GCM 四种模式 |

### 已知限制

| 问题 | 严重程度 | 说明 |
|------|---------|------|
| SM2 非常量时间 | ⚠️ 高 | 标量乘法中 `ec_point_add` 和 `bn_inv_mod` 执行时间依赖密钥位模式，存在时序侧信道风险 |
| 仿射坐标点运算 | ⚠️ 中 | 每次点加/倍点都需要模逆运算（代价高），生产环境应改用射影坐标 |
| GCM IV 处理 | ⚠️ 低 | 非 96 位 IV 的处理未完整实现（注释 `simplified: not shown`） |
| 随机数源 | ℹ️ 信息 | 使用 `/dev/urandom`，适合大多数场景；高安全场景可考虑 `/dev/random` 或 HWRNG |
| SA 并发访问 | ⚠️ 中 | VPP 插件未对 `sa->seq` 的自增操作加锁，多核环境可能产生序列号冲突 |

### 改进建议

1. **SM2 常量时间实现**：使用 Montgomery 梯形算法（`ladderstep`）或固定窗口算法，消除时序侧信道
2. **射影坐标优化**：将点运算切换到雅可比坐标系，将每次点加的模逆运算从 1 次减少到 0 次（代价是最后转换需要 1 次模逆）
3. **VPP 序列号原子操作**：使用 `__atomic_fetch_add` 保证多核下序列号单调递增
4. **GCM IV 规范化**：完整实现 GHASH 对非 96 位 IV 的处理

---

## 10. 总结

secgw 项目是一个架构清晰、实现完整的国密 IPSec 安全网关原型。

### 核心价值

- **国密合规**：完整实现了 SM2/SM3/SM4 三个核心国密算法，符合 GM/T 系列标准
- **工程完备性**：从底层密码实现到 IPSec 协议集成、配置文件，形成了一个完整的技术栈
- **可扩展性**：分层解耦的架构允许独立替换密码后端（如切换到硬件 SM4 引擎）或数据平面（如从 VPP 切换到 DPDK）
- **可测试性**：完善的单元测试和集成测试，覆盖算法正确性和安全属性

### 适用场景

| 场景 | 适用性 |
|------|-------|
| 国密合规性验证/研究 | ✅ 优秀 |
| 嵌入式/资源受限设备 | ✅ 良好（零依赖） |
| 生产高性能网关 | ⚠️ 需增强 SM2 安全性和 VPP 并发安全性 |
| DPDK 硬件加速部署 | ✅ 良好（有软件回退保障） |

项目为国内 5G 核心网、工业互联网、政务专网等对国密算法有合规要求的场景提供了一个可参考的 IPSec 安全网关实现框架。

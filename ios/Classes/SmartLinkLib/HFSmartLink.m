//
//  HFSmartLink.m
//  SmartlinkLib
//
//  Created by wangmeng on 15/3/16.
//  Copyright (c) 2015年 HF. All rights reserved.
//

#import "HFSmartLink.h"
#import "Udpproxy.h"

//#include "hf-pmk-generator.h"
typedef unsigned long size_t;
typedef unsigned char u8;
typedef unsigned int u32;

#include <string.h>

#define SHA1_MAC_LEN 20

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#ifndef WORDS_BIGENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i], 24) & 0xFF00FF00) | \
	(rol(block->l[i], 8) & 0x00FF00FF))
#else
#define blk0(i) block->l[i]
#endif

#define blk(i) (block->l[i & 15] = rol(block->l[(i + 13) & 15] ^ \
	block->l[(i + 8) & 15] ^ block->l[(i + 2) & 15] ^ block->l[i & 15], 1))
/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk0(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R1(v,w,x,y,z,i) \
	z += ((w & (x ^ y)) ^ y) + blk(i) + 0x5A827999 + rol(v, 5); \
	w = rol(w, 30);
#define R2(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0x6ED9EBA1 + rol(v, 5); w = rol(w, 30);
#define R3(v,w,x,y,z,i) \
	z += (((w | x) & y) | (w & x)) + blk(i) + 0x8F1BBCDC + rol(v, 5); \
	w = rol(w, 30);
#define R4(v,w,x,y,z,i) \
	z += (w ^ x ^ y) + blk(i) + 0xCA62C1D6 + rol(v, 5); \
	w=rol(w, 30);

struct SHA1Context {
	u32 state[5];
	u32 count[2];
	unsigned char buffer[64];
};

typedef struct SHA1Context SHA1_CTX;

/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}

void SHA1Transform(u32 state[5], const unsigned char buffer[64]);

/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const void *_data, u32 len)
{
	u32 i, j;
	const unsigned char *data = (const unsigned char *)_data;

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3))
		context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64-j));
		SHA1Transform(context->state, context->buffer);
		for ( ; i + 63 < len; i += 64) {
			SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
	u32 i;
	unsigned char finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)
			((context->count[(i >= 4 ? 0 : 1)] >>
			  ((3-(i & 3)) * 8) ) & 255);  /* Endian independent */
	}
	SHA1Update(context, (unsigned char *) "\200", 1);
	while ((context->count[0] & 504) != 448) {
		SHA1Update(context, (unsigned char *) "\0", 1);
	}
	SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform()
					      */
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)
			((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) &
			 255);
	}
	/* Wipe variables */
	i = 0;
	memset(context->buffer, 0, 64);
	memset(context->state, 0, 20);
	memset(context->count, 0, 8);
	memset(finalcount, 0, 8);
}

/**
 * sha1_vector - SHA-1 hash for data vector
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash
 * Returns: 0 on success, -1 of failure
 */
int sha1_vector(size_t num_elem, const u8 *addr[], const size_t *len, u8 *mac)
{
	SHA1_CTX ctx;
	size_t i;

	SHA1Init(&ctx);
	for (i = 0; i < num_elem; i++)
		SHA1Update(&ctx, addr[i], len[i]);
	SHA1Final(mac, &ctx);
	return 0;
}
/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(u32 state[5], const unsigned char buffer[64])
{
	u32 a, b, c, d, e;
	typedef union {
		unsigned char c[64];
		u32 l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;
#ifdef SHA1HANDSOFF
	CHAR64LONG16 workspace;
	block = &workspace;
	memcpy(block, buffer, 64);
#else
	block = (CHAR64LONG16 *) buffer;
#endif
	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	/* Wipe variables */
	a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
	memset(block, 0, 64);
#endif
}

/**
 * hmac_sha1_vector - HMAC-SHA1 over data vector (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @num_elem: Number of elements in the data vector
 * @addr: Pointers to the data areas
 * @len: Lengths of the data blocks
 * @mac: Buffer for the hash (20 bytes)
 * Returns: 0 on success, -1 on failure
 */
int hmac_sha1_vector(const u8 *key, size_t key_len, size_t num_elem,
		     const u8 *addr[], const size_t *len, u8 *mac)
{
	unsigned char k_pad[64]; /* padding - key XORd with ipad/opad */
	unsigned char tk[20];
	const u8 *_addr[6];
	size_t _len[6], i;

	if (num_elem > 5) {
		/*
		 * Fixed limit on the number of fragments to avoid having to
		 * allocate memory (which could fail).
		 */
		return -1;
	}

        /* if key is longer than 64 bytes reset it to key = SHA1(key) */
        if (key_len > 64) {
		if (sha1_vector(1, &key, &key_len, tk))
			return -1;
		key = tk;
		key_len = 20;
        }

	/* the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected */

	/* start out by storing key in ipad */
	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with ipad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x36;

	/* perform inner SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	for (i = 0; i < num_elem; i++) {
		_addr[i + 1] = addr[i];
		_len[i + 1] = len[i];
	}
	if (sha1_vector(1 + num_elem, _addr, _len, mac))
		return -1;

	memset(k_pad, 0, sizeof(k_pad));
	memcpy(k_pad, key, key_len);
	/* XOR key with opad values */
	for (i = 0; i < 64; i++)
		k_pad[i] ^= 0x5c;

	/* perform outer SHA1 */
	_addr[0] = k_pad;
	_len[0] = 64;
	_addr[1] = mac;
	_len[1] = SHA1_MAC_LEN;
	return sha1_vector(2, _addr, _len, mac);
}


/**
 * hmac_sha1 - HMAC-SHA1 over data buffer (RFC 2104)
 * @key: Key for HMAC operations
 * @key_len: Length of the key in bytes
 * @data: Pointers to the data area
 * @data_len: Length of the data area
 * @mac: Buffer for the hash (20 bytes)
 * Returns: 0 on success, -1 of failure
 */
int hmac_sha1(const u8 *key, size_t key_len, const u8 *data, size_t data_len,
	       u8 *mac)
{
	return hmac_sha1_vector(key, key_len, 1, &data, &data_len, mac);
}


/**
 * sha1_prf - SHA1-based Pseudo-Random Function (PRF) (IEEE 802.11i, 8.5.1.1)
 * @key: Key for PRF
 * @key_len: Length of the key in bytes
 * @label: A unique label for each purpose of the PRF
 * @data: Extra data to bind into the key
 * @data_len: Length of the data
 * @buf: Buffer for the generated pseudo-random key
 * @buf_len: Number of bytes of key to generate
 * Returns: 0 on success, -1 of failure
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key (e.g., PMK in IEEE 802.11i).
 */
int sha1_prf(const u8 *key, size_t key_len, const char *label,
	     const u8 *data, size_t data_len, u8 *buf, size_t buf_len)
{
	u8 counter = 0;
	size_t pos, plen;
	u8 hash[SHA1_MAC_LEN];
	size_t label_len = strlen(label) + 1;
	const unsigned char *addr[3];
	size_t len[3];

	addr[0] = (u8 *) label;
	len[0] = label_len;
	addr[1] = data;
	len[1] = data_len;
	addr[2] = &counter;
	len[2] = 1;

	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			if (hmac_sha1_vector(key, key_len, 3, addr, len,
					     &buf[pos]))
				return -1;
			pos += SHA1_MAC_LEN;
		} else {
			if (hmac_sha1_vector(key, key_len, 3, addr, len,
					     hash))
				return -1;
			memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}

	return 0;
}

static int pbkdf2_sha1_f(const char *passphrase, const char *ssid,
			 size_t ssid_len, int iterations, unsigned int count,
			 u8 *digest)
{
	unsigned char tmp[SHA1_MAC_LEN], tmp2[SHA1_MAC_LEN];
	int i, j;
	unsigned char count_buf[4];
	const u8 *addr[2];
	size_t len[2];
	size_t passphrase_len = strlen(passphrase);

	addr[0] = (u8 *) ssid;
	len[0] = ssid_len;
	addr[1] = count_buf;
	len[1] = 4;

	/* F(P, S, c, i) = U1 xor U2 xor ... Uc
	 * U1 = PRF(P, S || i)
	 * U2 = PRF(P, U1)
	 * Uc = PRF(P, Uc-1)
	 */

	count_buf[0] = (count >> 24) & 0xff;
	count_buf[1] = (count >> 16) & 0xff;
	count_buf[2] = (count >> 8) & 0xff;
	count_buf[3] = count & 0xff;
	if (hmac_sha1_vector((u8 *) passphrase, passphrase_len, 2, addr, len,
			     tmp))
		return -1;
	memcpy(digest, tmp, SHA1_MAC_LEN);

	for (i = 1; i < iterations; i++) {
		if (hmac_sha1((u8 *) passphrase, passphrase_len, tmp,
			      SHA1_MAC_LEN, tmp2))
			return -1;
		memcpy(tmp, tmp2, SHA1_MAC_LEN);
		for (j = 0; j < SHA1_MAC_LEN; j++)
			digest[j] ^= tmp2[j];
	}

	return 0;
}

/**
 * pbkdf2_sha1 - SHA1-based key derivation function (PBKDF2) for IEEE 802.11i
 * @passphrase: ASCII passphrase
 * @ssid: SSID
 * @ssid_len: SSID length in bytes
 * @iterations: Number of iterations to run
 * @buf: Buffer for the generated key
 * @buflen: Length of the buffer in bytes
 * Returns: 0 on success, -1 of failure
 *
 * This function is used to derive PSK for WPA-PSK. For this protocol,
 * iterations is set to 4096 and buflen to 32. This function is described in
 * IEEE Std 802.11-2004, Clause H.4. The main construction is from PKCS#5 v2.0.
 */
int pbkdf2_sha1(const char *passphrase, const char *ssid, size_t ssid_len,
		int iterations, u8 *buf, size_t buflen)
{
	unsigned int count = 0;
	unsigned char *pos = buf;
	size_t left = buflen, plen;
	unsigned char digest[SHA1_MAC_LEN];

	while (left > 0) {
		count++;
		if (pbkdf2_sha1_f(passphrase, ssid, ssid_len, iterations,
				  count, digest))
			return -1;
		plen = left > SHA1_MAC_LEN ? SHA1_MAC_LEN : left;
		memcpy(pos, digest, plen);
		pos += plen;
		left -= plen;
	}

	return 0;
}



#define SMTV30_BASELEN      76
#define SMTV30_STARTCODE      '\r'
#define SMTV30_STOPCODE       '\n'
#define V8_RANDOM_NUM          0xAA
#define PWD_USR_INTER          0x1B

// for 机智云
//#define GIZWITS

@implementation HFSmartLink{
    SmartLinkProcessBlock processBlock;
    SmartLinkSuccessBlock successBlock;
    SmartLinkFailBlock failBlock;
    SmartLinkStopBlock stopBlock;
    SmartLinkEndblock endBlock;
    //NSString * pswd;
    char pswd[200];
    int pswd_len;
    char cont[200];
    int cont_len;
    char v8Magic[4];
    char v8Prefix[4];
    char v8Data[300];
    int v8Data_len;
    int v8flyTime;
    BOOL isconnnecting;
    BOOL userStoping;
    NSInteger sendTime;
    NSMutableDictionary *deviceDic;
    Udpproxy * udp;
    BOOL withV3x;
}

+(instancetype)shareInstence{
    static HFSmartLink * me = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
         me = [[HFSmartLink alloc]init];
    });
    return me;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        /**
         *  初始化 套接字
         */
//        [UdpProxy shaInstence];
        udp = [Udpproxy shareInstence];
        deviceDic = [[NSMutableDictionary alloc]init];
        self.isConfigOneDevice = true;
        self.waitTimers = 60;//15;
        withV3x=true;
    }
    return self;
}

- (int)getStringLen:(NSString*)str
{
    int strlen=0;
    char *p=(char *)[str cStringUsingEncoding:NSUnicodeStringEncoding];
    for (int i=0;i<[str lengthOfBytesUsingEncoding:NSUnicodeStringEncoding];i++)
    {
        if (*p)
        {
            p++;
            strlen++;
        }
        else
        {
            p++;
        }
    }
    return strlen;
}

-(void)startWithSSID:(NSString*)ssidStr Key:(NSString*)pswdStr UserStr:(NSString *)userStr withV3x:(BOOL)v3x processblock:(SmartLinkProcessBlock)pblock successBlock:(SmartLinkSuccessBlock)sblock failBlock:(SmartLinkFailBlock)fblock endBlock:(SmartLinkEndblock)eblock

{
    NSLog(@"to send...");
    withV3x=v3x;
    if(udp){
        [udp CreateBindSocket];
    }else{
        udp = [Udpproxy shareInstence];
        [udp CreateBindSocket];
    }

    [self v8byteConvertSsid:ssidStr Key:pswdStr UserStr:userStr];
    
    int ssidLen=[self getStringLen:ssidStr];
    int pswdLen=[self getStringLen:pswdStr];
    int ustrLen=[self getStringLen:userStr];
    
    unsigned char buf[33];
    memset(buf, 0, 33);
    pbkdf2_sha1([pswdStr UTF8String], [ssidStr UTF8String], ssidLen, 4096, buf, 32);
    
    char contC[200];
    int contC_len=0;
    memset(contC,0,200);
    contC[contC_len++]=[self getStringLen:ssidStr];//[ssidStr length];
    contC[contC_len++]=[self getStringLen:pswdStr];//[pswdStr length];
    if (pswdLen!=0)
        contC[contC_len++]=32;
    else
        contC[contC_len++]=0;
    if (ustrLen==0)
    {
        contC[contC_len++]= 0;
    }
    else
    {
#ifdef GIZWITS
        contC[contC_len++]=ustrLen+2;
#else
        contC[contC_len++]=ustrLen;
#endif
    }
    sprintf(&(contC[contC_len]), "%s", [ssidStr UTF8String]);
    contC_len+=ssidLen;//[ssidStr length];
    sprintf(&(contC[contC_len]), "%s", [pswdStr UTF8String]);
    contC_len+=pswdLen;//[pswdStr length];
    if (pswdLen/*[pswdStr length]*/!=0)
    {
        memcpy(&(contC[contC_len]), buf, 32);
        contC_len+=32;
    }
    if (ustrLen>0)
    {
#ifdef GIZWITS
        contC[contC_len++]= 0x00;
        contC[contC_len++]= 0x1b;
#endif
        sprintf(&(contC[contC_len]), "%s", [userStr UTF8String]);
        contC_len+=ustrLen;
    }
    
    if (contC_len % 2!=0){
        contC_len++;
    }
    
 //   pswd=pswdStr;
    memset(pswd, 0, 200);
    sprintf(pswd, "%s", [pswdStr UTF8String]);
    pswd_len= pswdLen;
    if (ustrLen>0)
    {
#ifdef GIZWITS
        pswd[pswd_len++]= 0x00;
#endif
        pswd[pswd_len++]= 0x1b;
        sprintf(&(pswd[pswd_len]), "%s", [userStr UTF8String]);
        pswd_len+=ustrLen;
    }
    memcpy(cont, contC, contC_len);
    cont_len=contC_len;
    // print content
    NSLog(@"***To Print Content***");
    char output[500];
    memset(output, 0, 500);
    for (int i=0;i<cont_len;i++){
        sprintf(output, "%s %X", output, (unsigned char)cont[i]);
    }
    NSLog(@"%s", output);
    processBlock = pblock;
    successBlock = sblock;
    failBlock = fblock;
    endBlock = eblock;
    sendTime = 0;
    userStoping = false;
    [deviceDic removeAllObjects];
    if(isconnnecting){
        failBlock(@"is connecting ,please stop frist!");
        return ;
    }
    isconnnecting = true;
    //开始配置线程
    [[[NSOperationQueue alloc]init]addOperationWithBlock:^(){
        [self connectV70];
    }];
    
    [[[NSOperationQueue alloc]init]addOperationWithBlock:^(){
        [self doProcess];
    }];
}

- (void)doProcess
{
    NSLog(@"start waitting module msg ");
    NSInteger waitCount = 0;
    while (waitCount < self.waitTimers&&isconnnecting) {
        [udp sendSmartLinkFind];
        sleep(1);
        waitCount++;
        NSLog(@"waitCount=%ld", (long)waitCount);
        processBlock(waitCount*100/self.waitTimers);
    }
    isconnnecting = false;
}

-(void)stopWithBlock:(SmartLinkStopBlock)block{
    stopBlock = block;
    isconnnecting = false;
    userStoping = true;
}
-(void)closeWithBlock:(SmartLinkCloseBlock)block{
    if(isconnnecting){
        dispatch_async(dispatch_get_main_queue(), ^(){
            block(@"please stop connect frist",false);
        });
    }
    
    if(udp){
        [udp close];
        dispatch_async(dispatch_get_main_queue(), ^(){
            block(@"close Ok",true);
        });
    }else{
        dispatch_async(dispatch_get_main_queue(), ^(){
            block(@"udp sock is Closed,on need Close more",false);
        });
    }
}

#pragma Send and Rcv
-(void)connectV70{
    //开始接收线程
    [[[NSOperationQueue alloc]init]addOperationWithBlock:^(){
        NSLog(@"start recv");
        [self recvNewModule];
    }];

    int flyTime=0;      // unit:10ms
    while (isconnnecting) {
        char cip[20];
        char c[100];
        memset(c, 0, 100);
        int sn=0;
        
        for (int i=0;i<sn+30;i++){
            c[i]='a';
        }
        
        for (int i=0;i<5;i++){
            [udp sendMCast:c withAddr:"239.48.0.0" andSN:0];
            usleep(10000);
            [self sendSmtlkV30:flyTime];
            flyTime++;
        }
        
        while (isconnnecting&&(sn*2<cont_len)) {
            memset(cip, 0, 20);
            sprintf(cip, "239.46.%d.%d",(unsigned char)cont[sn*2],(unsigned char)cont[sn*2+1]);
//            NSLog(@"%X %X", (unsigned char)cont[sn*2],(unsigned char)cont[sn*2+1]);
            [udp sendMCast:c withAddr:cip andSN:0];
            usleep(10000);
            [self sendSmtlkV30:flyTime];
            flyTime++;
            c[sn+30]='a';
            sn++;
        }

        for (int i=0;i<5;i++){
            usleep(10000);
            [self sendSmtlkV30:flyTime];
            flyTime++;
        }
        
//        if (isconnnecting){
//            sendTime++;
//            NSLog(@"send time %d",sendTime);
//            dispatch_async(dispatch_get_main_queue(), ^(){
//                processBlock(sendTime);
//            });
//        }
    }
}

- (void) sendSmtlkV30:(int)ft
{
    if (withV3x==false)
    {
        [self sendV8Data:ft];
        return;
    }
    
    while (ft>= 200+(3+pswd_len+6)*5){
        ft-=200+(3+pswd_len+6)*5;
    }
    
    if (ft< 200){
        [self sendOnePackageByLen:SMTV30_BASELEN];
    }else if (ft % 5 == 0){
        int ft5=(ft-200)/5;
        if (ft5<3){
            [self sendOnePackageByLen:SMTV30_BASELEN+SMTV30_STARTCODE];
        }else if (ft5<3+pswd_len){
            int code=SMTV30_BASELEN+ pswd[ft5-3];//[pswd characterAtIndex:(ft5-3)];
            [self sendOnePackageByLen:code];
            NSLog(@"code:%X", (unsigned char)pswd[ft5-3]);//[pswd characterAtIndex:(ft5-3)]);
        }else if (ft5<3+pswd_len+3){
            [self sendOnePackageByLen:SMTV30_BASELEN+SMTV30_STOPCODE];
        }else if (ft5< 3+pswd_len+6){
            [self sendOnePackageByLen:SMTV30_BASELEN+pswd_len+256];
        }
    }
}

-(void)sendOnePackageByLen:(NSInteger)len{
    char data[len+1];
    memset(data, 5, len);
    data[len]='\0';
    [udp send:data];
}
-(void)recvNewModule{
    while (isconnnecting) {
        HFSmartLinkDeviceInfo * dev = [udp recv:V8_RANDOM_NUM];
        if(dev == nil){
            continue;
        }
        
        if([deviceDic objectForKey:dev.mac] != nil){
            continue;
        }

        [deviceDic setObject:dev forKey:dev.mac];
        
        dispatch_async(dispatch_get_main_queue(), ^(){
            successBlock(dev);
        });
        
        if (self.isConfigOneDevice) {
            NSLog(@"end config once");
            isconnnecting = false;
            dispatch_async(dispatch_get_main_queue(), ^(){
                endBlock(deviceDic);
            });
            [udp close];
            return ;
        }
    }
    
    if(userStoping){
        dispatch_async(dispatch_get_main_queue(), ^(){
            stopBlock(@"stop connect ok",true);
        });
    }
    
    if(deviceDic.count <= 0&&!userStoping){
        dispatch_async(dispatch_get_main_queue(), ^(){
            failBlock(@"smartLink fail ,no device is configed");
        });
    }
    
    [udp close];
    
    dispatch_async(dispatch_get_main_queue(), ^(){
        endBlock(deviceDic);
    });
}

- (int) getByte:(unsigned char *)bytes pos:(int)pos
{
    if (pos<20*4+4)
    {
        return bytes[pos]+1;
    }
    else
    {
        int itmp= pos- 20*4-4;
        int mod= itmp % 6;
        if (mod==0 || mod==1)
        {
            return bytes[pos]+1;
        }
        else
        {
            return bytes[pos]+0x0100+1;
        }
    }
}

int headNum= 40;
int magicNum= 20;
int prefixNum= 20;
int dataLoops= 15;

- (void) sendV8Data:(int)ft
{
    int bsend[10];
    static int tm= 0;
    tm++;
    if (tm>=5)
    {
        tm=0;
        int len= [self getByteRet:bsend rLen:10];
        v8flyTime++;
        if (len<=0)
        {
            v8flyTime= 0;
            NSLog(@"Restart Airkiss");
        }
        else
            for (int i=0; i<len; i++)
            {
                NSLog(@"Send:%d, 0x%02X\n", bsend[i], bsend[i]);
                if (bsend[i]==0)
                    bsend[i]= 8;
                [self sendOnePackageByLen:bsend[i]];
                usleep(5000);
            }
    }
}

- (int) getByteRet:(int *)ret rLen:(int)len
{
    NSLog(@"flyTime:%d\n", v8flyTime);
    if (v8flyTime<headNum)
    {
        memset(ret, 0, len);
        for (int i=0; i<4; i++)
            ret[i]= i+1;
        return 4;
    }
    else if (v8flyTime < headNum+magicNum)
    {
        memset(ret, 0, len);
        for (int i=0; i<4; i++)
            ret[i]= (v8Magic[i] & 0x0FF);
        return 4;
    }
    else if (v8flyTime < headNum+magicNum+prefixNum)
    {
        memset(ret, 0, len);
        for (int i=0; i<4; i++)
            ret[i]= (v8Prefix[i] & 0x0FF);
        return 4;
    }
    else
    {
        int blocks= v8Data_len /6;
        if (blocks * 6 < v8Data_len)
            blocks++;
        int loop= (v8flyTime-headNum-magicNum-prefixNum) / blocks;
        if (loop >= dataLoops)
            return -1;
        else
        {
            int blockIdx= (v8flyTime - headNum-magicNum-prefixNum) % blocks;
            int pos= blockIdx * 6;
            int len= 6;
            if (pos+len > v8Data_len)
                len= v8Data_len- pos;
            memset(ret, 0, len);
            ret[0]= v8Data[pos] & 0x0FF;
            ret[1]= v8Data[pos+1] & 0x0FF;
            for (int i=2; i<len; i++)
                ret[i]= (v8Data[pos+i] & 0x0FF) + 0x0100;
            return len;
        }
    }
}

- (void) v8byteConvertSsid:(NSString*)ssidStr Key:(NSString*)pswdStr UserStr:(NSString *)userStr
{
    int bPwdUsrLen= (int)[self getStringLen:pswdStr];
    if ([self getStringLen:userStr]>0)
        bPwdUsrLen+= [self getStringLen:userStr]+1;
    else
    {
#ifdef GIZWITS
        bPwdUsrLen+=2;
#else
        bPwdUsrLen+=1;
#endif
    }
    int dLen= bPwdUsrLen+1+(int)[self getStringLen:ssidStr];
    char bData[200];
    memset(bData, 0, 200);
    int pos= 0;
    sprintf(&(bData[pos]), "%s", [pswdStr UTF8String]);
    pos+= [self getStringLen:pswdStr];
#ifdef GIZWITS
    bData[pos++]= 0x00;
#endif
    bData[pos++]= 0x1b;
    if ([self getStringLen:userStr]>0)
    {
        sprintf(&(bData[pos]), "%s", [userStr UTF8String]);
        pos+= [self getStringLen:userStr];
    }
    bData[pos++]= V8_RANDOM_NUM;         // this is the random num
    sprintf(&(bData[pos]), "%s", [ssidStr UTF8String]);
    pos+= [self getStringLen:ssidStr];
    
    char tmp[64];
    memset(tmp, 0, 64);
    sprintf(tmp, "%s", [ssidStr UTF8String]);
    int ssidCrc= [self crc8:(unsigned char *)tmp len:(int)[self getStringLen:ssidStr]];
    [self getMagicBytes:dLen ssidCrc:ssidCrc Ret:v8Magic];
    
    int pLen=bPwdUsrLen;
    memset(tmp, 0, 64);
    int plbLen= [self itob:pLen Ret:tmp];
    int plCrc= [self crc8:(unsigned char *)tmp len:plbLen];
    [self getPrefixBytes:pLen plCrc:plCrc Ret:v8Prefix];
    
    int dblocks= dLen/4;
    if (dblocks*4 < dLen)
    {
        dblocks++;
    }
    v8Data_len= 0;
    pos= 0;
    for (int i=0; i<dblocks; i++)
    {
        v8Data_len+=[self getBlockBytes:bData pos:&pos len:dLen Ret:&(v8Data[v8Data_len])];
    }
    v8flyTime= 0;
}

- (int) getBlockBytes:(char *)data pos:(int *)pos len:(int)dlen Ret:(char *)ret
{
    int len=dlen- *pos;
    if (len>4){
        len= 4;
    }
    int retLen=len+2;
    memset(ret, 0, retLen);
    ret[1]= (*pos/4);
    for (int i=0; i<len; i++)
    {
        ret[2+i]= *(data+*pos+i);
    }
    int crc= [self crc8:(unsigned char *)&(ret[1]) len:len+1];
    ret[0]= 0x80 | (crc & 0x7F);
    ret[1]= 0x80 | ret[1];
    NSLog(@"Block pos=%d:", *pos);
    for (int i=0; i<retLen; i++)
    {
        NSLog(@"%02X ", (unsigned char)ret[i]);
    }
    NSLog(@"\n");
    (*pos)+=len;
    return retLen;
}

- (int) getMagicBytes:(int)dLen ssidCrc:(int)ssidCrc Ret:(char *)ret
{
    int retLen= 4;
    memset(ret, 0, retLen);
    ret[0]= 0x000 | ((dLen>>4)&0x0F);
    ret[1]= 0x010 | ((dLen>>0)&0x0F);
    ret[2]= 0x020 | ((ssidCrc>>4)&0x0F);
    ret[3]= 0x030 | ((ssidCrc>>0)&0x0F);
    NSLog(@"Magic:%02X %02X %02X %02X\n", ret[0], ret[1], ret[2], ret[3]);
    return retLen;
}

- (int) getPrefixBytes:(int)pLen plCrc:(int)plCrc Ret:(char *)ret
{
    int retLen= 4;
    memset(ret, 0, retLen);
    ret[0]= 0x040 | ((pLen>>4)&0x0F);
    ret[1]= 0x050 | ((pLen>>0)&0x0F);
    ret[2]= 0x060 | ((plCrc>>4)&0x0F);
    ret[3]= 0x070 | ((plCrc>>0)&0x0F);
    NSLog(@"Prefix:%02X %02X %02X %02X\n", ret[0], ret[1], ret[2], ret[3]);
    return retLen;
}

- (int) itob:(int)i Ret:(char *)ret
{
    int bLen= 0;
    if (i > 0x0FFFFFF)
        bLen= 4;
    else if (i > 0x0FFFF)
        bLen= 3;
    else if (i > 0x0FF)
        bLen= 2;
    else
        bLen= 1;
    for (int n=0; n<bLen; n++)
    {
        ret[n]= (i>>(8*n))&0x0FF;
    }
    return bLen;
}

- (int) crc8:(unsigned char *)ptr len:(int)len
{
    unsigned char crc;
    unsigned char i, data;
    crc= 0;
    while (len--) {
        data= (*ptr)&0xff;
        crc ^= data;
        for (i=0; i<8; i++)
        {
            if (crc & 0x01)
            {
                crc= (crc>>1)^0x8c;
            }
            else
            {
                crc >>=1;
            }
        }
        ptr++;
    }
    return crc;
}
@end

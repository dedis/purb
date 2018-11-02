# Padded Uniform Random Blobs [![Build Status](https://travis-ci.org/dedis/paper_purbs.svg?branch=master)](https://travis-ci.org/dedis/paper_purbs)

A library for a novel encoding approach preventing metadata leakage for encrypted communication and data at rest.

```
make install
make example
```

The folder `experiments-encoding` contains simulation about PURBs encoding and decoding, and the duration of those operations.

The folder `experiments-padding` contains an evaluation of Padmé, the padding algorithm for PURBs.

## Example

Message: And presently I was driving through the drizzle of the dying day, with the windshield wipers in full action but unable to cope with my tears.
```
00000000  41 6e 64 20 70 72 65 73  65 6e 74 6c 79 20 49 20  |And presently I |
00000010  77 61 73 20 64 72 69 76  69 6e 67 20 74 68 72 6f  |was driving thro|
00000020  75 67 68 20 74 68 65 20  64 72 69 7a 7a 6c 65 20  |ugh the drizzle |
00000030  6f 66 20 74 68 65 20 64  79 69 6e 67 20 64 61 79  |of the dying day|
00000040  2c 20 77 69 74 68 20 74  68 65 20 77 69 6e 64 73  |, with the winds|
00000050  68 69 65 6c 64 20 77 69  70 65 72 73 20 69 6e 20  |hield wipers in |
00000060  66 75 6c 6c 20 61 63 74  69 6f 6e 20 62 75 74 20  |full action but |
00000070  75 6e 61 62 6c 65 20 74  6f 20 63 6f 70 65 20 77  |unable to cope w|
00000080  69 74 68 20 6d 79 20 74  65 61 72 73 2e           |ith my tears.|
```

PURB for 1 recipient, 1 suite (Curve 25519):
```
00000000  d7 6f be d6 fd 26 30 c1  24 76 80 a2 a8 34 db c9  |.o...&0.$v...4..|
00000010  48 22 3e 0d f6 cd 29 99  58 39 34 e6 3d 0e 04 55  |H">...).X94.=..U|
00000020  2d 0a 53 33 f4 ba 45 2b  62 e1 19 29 ba 3d 66 db  |-.S3..E+b..).=f.|
00000030  35 06 f4 f6 bc 60 45 dc  36 a5 31 b7 14 46 1d 65  |5....`E.6.1..F.e|
00000040  b7 fc 96 1e b0 6f ba bc  24 2c dc fb b7 58 92 8d  |.....o..$,...X..|
00000050  1a 81 9c dd 6c ff de 51  e2 e6 ce fd fd ff 12 22  |....l..Q......."|
00000060  10 42 8a d3 31 21 13 e2  b7 a7 92 b2 50 03 25 93  |.B..1!......P.%.|
00000070  02 aa c1 92 6c ce 1a 78  89 ae 18 44 45 05 b2 c9  |....l..x...DE...|
00000080  70 11 39 82 46 ad e3 ce  28 9d ea 24 5f 81 0d eb  |p.9.F...(..$_...|
00000090  82 c8 3f 7a 99 15 05 c2  7e 29 a4 47 33 35 b5 82  |..?z....~).G35..|
000000a0  1d 03 42 af 96 b9 1d 2e  d0 13 9d bb 63 6d 86 0e  |..B.........cm..|
000000b0  b3 c3 9b 28 94 d6 9a a5  be 75 3a 47 8a 45 0b 27  |...(.....u:G.E.'|
000000c0  87 0a d9 74 ba 9b 44 c2  13 33 95 3d a4 a7 4d df  |...t..D..3.=..M.|
000000d0  be fc b7 63 0f 9e 0a 20  b8 91 82 54 aa 7e 9a 80  |...c... ...T.~..|
```

PURB's internal structure:
```
*** PURB Details ***
Original Data: len 141
PURB: header at 0 (len 64), payload at 64 (len 160), total 224 bytes
Nonce: [215 111 190 214 253 38 48 193 36 118 128 162] (len 12)
Cornerstones: Curve25519-full @ offset 12 (len 32)
  Value: [29 139 149 106 253 70 52 19 191 118 115 255 153 27 185 82 95 120 30 123 247 228 190 0 148 193 1 119 190 67 178 77]
  Allowed positions for this suite: [12 44 108 140]
  Positions used: [12:44 44:76 108:140 140:172]
  Value @ pos[12:44]: [168 52 219 201 72 34 62 13 246 205 41 153 88 57 52 230 61 14 4 85 45 10 83 51 244 186 69 43 98 225 25 41]
  Value @ pos[44:76]: [186 61 102 219 53 6 244 246 188 96 69 220 54 165 49 183 20 70 29 101 183 252 150 30 176 111 186 188 36 44 220 251]
  Value @ pos[108:140]: [80 3 37 147 2 170 193 146 108 206 26 120 137 174 24 68 69 5 178 201 112 17 57 130 70 173 227 206 40 157 234 36]
  Value @ pos[140:172]: [95 129 13 235 130 200 63 122 153 21 5 194 126 41 164 71 51 53 181 130 29 3 66 175 150 185 29 46 208 19 157 187]
  Recomputed value: [29 139 149 106 253 70 52 19 191 118 115 255 153 27 185 82 95 120 30 123 247 228 190 0 148 193 1 119 190 67 178 77]
Entrypoints for suite Curve25519-full
  Entrypoints [0]: [181 83 39 220 28 56 39 143 209 124 116 63 122 47 250 58 174 18 221 7 251 126 201 84 198 40 181 221 5 93 228 95] @ offset 44 (len 20)
Padded Payload: [183 252 150 30 176 111 186 188 36 44 220 251 183 88 146 141 26 129 156 221 108 255 222 81 226 230 206 253 253 255 18 34 16 66 138 211 49 33 19 226 183 167 146 178 80 3 37 147 2 170 193 146 108 206 26 120 137 174 24 68 69 5 178 201 112 17 57 130 70 173 227 206 40 157 234 36 95 129 13 235 130 200 63 122 153 21 5 194 126 41 164 71 51 53 181 130 29 3 66 175 150 185 29 46 208 19 157 187 99 109 134 14 179 195 155 40 148 214 154 165 190 117 58 71 138 69 11 39 135 10 217 116 186 155 68 194 19 51 149 61 164 167 77 223 190 252 183 99 15 158 10 32 184 145 130 84 170 126 154 128] @ offset 64 (len 160)
```

Decryption:
```
Success: true
Error message: <nil>
And presently I was driving through the drizzle of the dying day, with the windshield wipers in full action but unable to cope with my tears.
00000000  41 6e 64 20 70 72 65 73  65 6e 74 6c 79 20 49 20  |And presently I |
00000010  77 61 73 20 64 72 69 76  69 6e 67 20 74 68 72 6f  |was driving thro|
00000020  75 67 68 20 74 68 65 20  64 72 69 7a 7a 6c 65 20  |ugh the drizzle |
00000030  6f 66 20 74 68 65 20 64  79 69 6e 67 20 64 61 79  |of the dying day|
00000040  2c 20 77 69 74 68 20 74  68 65 20 77 69 6e 64 73  |, with the winds|
00000050  68 69 65 6c 64 20 77 69  70 65 72 73 20 69 6e 20  |hield wipers in |
00000060  66 75 6c 6c 20 61 63 74  69 6f 6e 20 62 75 74 20  |full action but |
00000070  75 6e 61 62 6c 65 20 74  6f 20 63 6f 70 65 20 77  |unable to cope w|
00000080  69 74 68 20 6d 79 20 74  65 61 72 73 2e           |ith my tears.|
```

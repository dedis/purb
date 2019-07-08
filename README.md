# Padded Uniform Random Blobs [![Build Status](https://travis-ci.org/dedis/purb.svg?branch=master)](https://travis-ci.org/dedis/purb)

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
00000000  97 ae 12 f3 55 c4 48 2a  11 7c 7a 33 2f 86 ca 99  |....U.H*.|z3/...|
00000010  dd f6 8a 8a 92 3f 23 b9  3c 46 62 44 ce 3f ea 6c  |.....?#.<FbD.?.l|
00000020  fd e4 0c f9 36 65 60 d0  6e e7 a1 a5 bb 47 0c dc  |....6e`.n....G..|
00000030  85 4a e5 b8 17 e5 2c 43  58 ff e8 6e a0 b1 89 3d  |.J....,CX..n...=|
00000040  1c 29 8e 15 47 65 8a b2  14 c6 66 b2 63 d5 e1 c8  |.)..Ge....f.c...|
00000050  c9 9f b3 3d 86 a2 ed af  4a 44 92 8e 37 1e e8 ec  |...=....JD..7...|
00000060  ee 41 52 ca 30 7e 15 9c  cf 17 0a 18 77 6a 7c cd  |.AR.0~......wj|.|
00000070  be 86 a7 ba 7b 3e 2c ba  bd 68 86 bf 8f 45 49 cf  |....{>,..h...EI.|
00000080  36 b7 dd 5f 12 20 77 bf  79 4f d5 b0 18 ee d2 26  |6.._. w.yO.....&|
00000090  a9 be 97 3c 5b 80 bb 6d  2c 0e 9f 99 2e 29 29 b4  |...<[..m,....)).|
000000a0  78 dd c4 b4 78 2b 15 32  6d 3d c7 20 66 10 be 85  |x...x+.2m=. f...|
000000b0  f4 c3 20 2a 93 92 3a a3  9e 97 68 bb 83 e7 b9 34  |.. *..:...h....4|
000000c0  96 09 46 79 7d 2f e3 cc  e4 a0 5f 80 2b 17 06 59  |..Fy}/...._.+..Y|
000000d0  83 1b 8c 95 63 57 08 19  8f 0d 9a c4 6c dd 22 cc  |....cW......l.".|
000000e0  01 91 c4 6c 72 99 65 e2  1d e9 7f 9f ba 38 03 e5  |...lr.e......8..|
000000f0  93 84 28 6f 3a ae a6 82  30 60 c6 f0 ee a7 22 e1  |..(o:...0`....".|
```

PURB's internal structure:
```
*** PURB Details ***
Original Data: len 141
PURB: header at 0 (len 80), payload at 80 (len 144), total 256 bytes
Nonce: [151 174 18 243 85 196 72 42 17 124 122 51] (len 12)
Cornerstones: Curve25519-full @ offset 12 (len 32)
  Value: [251 69 104 174 79 132 95 180 165 100 152 45 245 223 147 12 207 226 3 42 175 167 155 7 27 11 136 239 110 83 213 135]
  Allowed positions for this suite: [12 44 108 140]
  Positions used: [12:44 44:76 108:140 140:172]
  Value @ pos[12:44]: [47 134 202 153 221 246 138 138 146 63 35 185 60 70 98 68 206 63 234 108 253 228 12 249 54 101 96 208 110 231 161 165]
  Value @ pos[44:76]: [187 71 12 220 133 74 229 184 23 229 44 67 88 255 232 110 160 177 137 61 28 41 142 21 71 101 138 178 20 198 102 178]
  Value @ pos[108:140]: [119 106 124 205 190 134 167 186 123 62 44 186 189 104 134 191 143 69 73 207 54 183 221 95 18 32 119 191 121 79 213 176]
  Value @ pos[140:172]: [24 238 210 38 169 190 151 60 91 128 187 109 44 14 159 153 46 41 41 180 120 221 196 180 120 43 21 50 109 61 199 32]
  Recomputed value: [251 69 104 174 79 132 95 180 165 100 152 45 245 223 147 12 207 226 3 42 175 167 155 7 27 11 136 239 110 83 213 135]
Entrypoints for suite Curve25519-full
  Entrypoints [0]: [39 149 223 250 186 177 116 42 49 215 24 73 29 209 55 115 112 31 185 210 33 221 98 5 49 181 182 149 97 14 217 222] @ offset 44 (len 36)
Padded Payload: [201 159 179 61 134 162 237 175 74 68 146 142 55 30 232 236 238 65 82 202 48 126 21 156 207 23 10 24 119 106 124 205 190 134 167 186 123 62 44 186 189 104 134 191 143 69 73 207 54 183 221 95 18 32 119 191 121 79 213 176 24 238 210 38 169 190 151 60 91 128 187 109 44 14 159 153 46 41 41 180 120 221 196 180 120 43 21 50 109 61 199 32 102 16 190 133 244 195 32 42 147 146 58 163 158 151 104 187 131 231 185 52 150 9 70 121 125 47 227 204 228 160 95 128 43 23 6 89 131 27 140 149 99 87 8 25 143 13 154 196 108 221 34 204] @ offset 80 (len 144)
MAC: [1 145 196 108 114 153 101 226 29 233 127 159 186 56 3 229 147 132 40 111 58 174 166 130 48 96 198 240 238 167 34 225] @ offset 224 (len 32)
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

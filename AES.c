#include <string.h>


#define BPOLY 0x1b //!< Lower 8 bits of (x^8+x^4+x^3+x+1), ie. (x^4+x^3+x+1).
#define BLOCKSIZE 16 //!< Block size in number of bytes.

#define KEY_COUNT 3

#if KEY_COUNT == 1
  #define KEYBITS 128 //!< Use AES128.
#elif KEY_COUNT == 2
  #define KEYBITS 192 //!< Use AES196.
#elif KEY_COUNT == 3
  #define KEYBITS 256 //!< Use AES256.
#else
  #error Use 1, 2 or 3 keys!
#endif

#if KEYBITS == 128
  #define ROUNDS 10 //!< Number of rounds.
  #define KEYLENGTH 16 //!< Key length in number of bytes.
#elif KEYBITS == 192
  #define ROUNDS 12 //!< Number of rounds.
  #define KEYLENGTH 24 //!< // Key length in number of bytes.
#elif KEYBITS == 256
  #define ROUNDS 14 //!< Number of rounds.
  #define KEYLENGTH 32 //!< Key length in number of bytes.
#else
  #error Key must be 128, 192 or 256 bits!
#endif


#define EXPANDED_KEY_SIZE (BLOCKSIZE * (ROUNDS+1)) //!< 176, 208 or 240 bytes.

unsigned char AES_Key_Table[32] =
{
  0xd0, 0x94, 0x3f, 0x8c, 0x29, 0x76, 0x15, 0xd8,
  0x20, 0x40, 0xe3, 0x27, 0x45, 0xd8, 0x48, 0xad,
  0xea, 0x8b, 0x2a, 0x73, 0x16, 0xe9, 0xb0, 0x49,
  0x45, 0xb3, 0x39, 0x28, 0x0a, 0xc3, 0x28, 0x3c,
};

unsigned char chainCipherBlock[32]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};//¼ÓÃÜÃÜÂë

unsigned char block1[256]; //!< Workspace 1.
unsigned char block2[256]; //!< Worksapce 2.
unsigned char tempbuf[256];

unsigned char *powTbl; //!< Final location of exponentiation lookup table.
unsigned char *logTbl; //!< Final location of logarithm lookup table.
unsigned char *sBox; //!< Final location of s-box.
unsigned char *sBoxInv; //!< Final location of inverse s-box.
unsigned char *expandedKey; //!< Final location of expanded key.

void CalcPowLog(unsigned char *powTbl, unsigned char *logTbl)
{
	unsigned char i = 0;
	unsigned char t = 1;
	
	do {
		// Use 0x03 as root for exponentiation and logarithms.
		powTbl[i] = t;
		logTbl[t] = i;
		i++;
		
		// Muliply t by 3 in GF(2^8).
		t ^= (t << 1) ^ (t & 0x80 ? BPOLY : 0);
	}while( t != 1 ); // Cyclic properties ensure that i < 255.
	
	powTbl[255] = powTbl[0]; // 255 = '-0', 254 = -1, etc.
}

void CalcSBox( unsigned char * sBox )
{
	unsigned char i, rot;
	unsigned char temp;
	unsigned char result;
	
	// Fill all entries of sBox[].
	i = 0;
	do {
		//Inverse in GF(2^8).
		if( i > 0 ) 
		{
			temp = powTbl[ 255 - logTbl[i] ];
		} 
		else 
		{
			temp = 0;
		}
		
		// Affine transformation in GF(2).
		result = temp ^ 0x63; // Start with adding a vector in GF(2).
		for( rot = 0; rot < 4; rot++ )
		{
			// Rotate left.
			temp = (temp<<1) | (temp>>7);
			
			// Add rotated byte in GF(2).
			result ^= temp;
		}
		
		// Put result in table.
		sBox[i] = result;
	} while( ++i != 0 );
}

void CalcSBoxInv( unsigned char * sBox, unsigned char * sBoxInv )
{
	unsigned char i = 0;
	unsigned char j = 0;
	
	// Iterate through all elements in sBoxInv using  i.
	do {
	// Search through sBox using j.
		do {
			// Check if current j is the inverse of current i.
			if( sBox[ j ] == i )
			{
				// If so, set sBoxInc and indicate search finished.
				sBoxInv[ i ] = j;
				j = 255;
			}
		} while( ++j != 0 );
	} while( ++i != 0 );
}

void CycleLeft( unsigned char * row )
{
	// Cycle 4 bytes in an array left once.
	unsigned char temp = row[0];
	
	row[0] = row[1];
	row[1] = row[2];
	row[2] = row[3];
	row[3] = temp;
}

void InvMixColumn( unsigned char * column )
{
	unsigned char r0, r1, r2, r3;
	
	r0 = column[1] ^ column[2] ^ column[3];
	r1 = column[0] ^ column[2] ^ column[3];
	r2 = column[0] ^ column[1] ^ column[3];
	r3 = column[0] ^ column[1] ^ column[2];
	
	column[0] = (column[0] << 1) ^ (column[0] & 0x80 ? BPOLY : 0);
	column[1] = (column[1] << 1) ^ (column[1] & 0x80 ? BPOLY : 0);
	column[2] = (column[2] << 1) ^ (column[2] & 0x80 ? BPOLY : 0);
	column[3] = (column[3] << 1) ^ (column[3] & 0x80 ? BPOLY : 0);
	
	r0 ^= column[0] ^ column[1];
	r1 ^= column[1] ^ column[2];
	r2 ^= column[2] ^ column[3];
	r3 ^= column[0] ^ column[3];
	
	column[0] = (column[0] << 1) ^ (column[0] & 0x80 ? BPOLY : 0);
	column[1] = (column[1] << 1) ^ (column[1] & 0x80 ? BPOLY : 0);
	column[2] = (column[2] << 1) ^ (column[2] & 0x80 ? BPOLY : 0);
	column[3] = (column[3] << 1) ^ (column[3] & 0x80 ? BPOLY : 0);
	
	r0 ^= column[0] ^ column[2];
	r1 ^= column[1] ^ column[3];
	r2 ^= column[0] ^ column[2];
	r3 ^= column[1] ^ column[3];
	
	column[0] = (column[0] << 1) ^ (column[0] & 0x80 ? BPOLY : 0);
	column[1] = (column[1] << 1) ^ (column[1] & 0x80 ? BPOLY : 0);
	column[2] = (column[2] << 1) ^ (column[2] & 0x80 ? BPOLY : 0);
	column[3] = (column[3] << 1) ^ (column[3] & 0x80 ? BPOLY : 0);
	
	column[0] ^= column[1] ^ column[2] ^ column[3];
	r0 ^= column[0];
	r1 ^= column[0];
	r2 ^= column[0];
	r3 ^= column[0];
	
	column[0] = r0;
	column[1] = r1;
	column[2] = r2;
	column[3] = r3;
}

void SubBytes( unsigned char * bytes, unsigned char count )
{
	do {
		*bytes = sBox[ *bytes ]; // Substitute every byte in state.
		bytes++;
	} while( --count );
}

void InvSubBytesAndXOR( unsigned char * bytes, unsigned char * key, unsigned char count )
{
	do {
		// *bytes = sBoxInv[ *bytes ] ^ *key; // Inverse substitute every byte in state and add key.
		*bytes = block2[ *bytes ] ^ *key; // Use block2 directly. Increases speed.
		bytes++;
		key++;
	} while( --count );
}

void InvShiftRows( unsigned char * state )
{
	unsigned char temp;
	
	// Note: State is arranged column by column.
	
	// Cycle second row right one time.
	temp = state[ 1 + 3*4 ];
	state[ 1 + 3*4 ] = state[ 1 + 2*4 ];
	state[ 1 + 2*4 ] = state[ 1 + 1*4 ];
	state[ 1 + 1*4 ] = state[ 1 + 0*4 ];
	state[ 1 + 0*4 ] = temp;
	
	// Cycle third row right two times.
	temp = state[ 2 + 0*4 ];
	state[ 2 + 0*4 ] = state[ 2 + 2*4 ];
	state[ 2 + 2*4 ] = temp;
	temp = state[ 2 + 1*4 ];
	state[ 2 + 1*4 ] = state[ 2 + 3*4 ];
	state[ 2 + 3*4 ] = temp;
	
	// Cycle fourth row right three times, ie. left once.
	temp = state[ 3 + 0*4 ];
	state[ 3 + 0*4 ] = state[ 3 + 1*4 ];
	state[ 3 + 1*4 ] = state[ 3 + 2*4 ];
	state[ 3 + 2*4 ] = state[ 3 + 3*4 ];
	state[ 3 + 3*4 ] = temp;
}

void InvMixColumns( unsigned char * state )
{
	InvMixColumn( state + 0*4 );
	InvMixColumn( state + 1*4 );
	InvMixColumn( state + 2*4 );
	InvMixColumn( state + 3*4 );
}

void XORBytes( unsigned char * bytes1, unsigned char * bytes2, unsigned char count )
{
	do {
		*bytes1 ^= *bytes2; // Add in GF(2), ie. XOR.
		bytes1++;
		bytes2++;
	} while( --count );
}

void CopyBytes( unsigned char * to, unsigned char * from, unsigned char count )
{
	do {
		*to = *from;
		to++;
		from++;
	} while( --count );
}

void KeyExpansion( unsigned char * expandedKey )
{
	unsigned char temp[4];
	unsigned int i;
	unsigned char Rcon[4] = { 0x01, 0x00, 0x00, 0x00 }; // Round constant.
	
	unsigned char * key = AES_Key_Table;
	
	// Copy key to start of expanded key.
	i = KEYLENGTH;
	do {
		*expandedKey = *key;
		expandedKey++;
		key++;
	} while( --i );
	
	// Prepare last 4 bytes of key in temp.
	expandedKey -= 4;
	temp[0] = *(expandedKey++);
	temp[1] = *(expandedKey++);
	temp[2] = *(expandedKey++);
	temp[3] = *(expandedKey++);
	
	// Expand key.
	i = KEYLENGTH;
	while( i < BLOCKSIZE*(ROUNDS+1) ) 
	{
		// Are we at the start of a multiple of the key size?
		if( (i % KEYLENGTH) == 0 )
		{
			CycleLeft( temp ); // Cycle left once.
			SubBytes( temp, 4 ); // Substitute each byte.
			XORBytes( temp, Rcon, 4 ); // Add constant in GF(2).
			*Rcon = (*Rcon << 1) ^ (*Rcon & 0x80 ? BPOLY : 0);
		}
		
		// Keysize larger than 24 bytes, ie. larger that 192 bits?
		#if KEYLENGTH > 24
		// Are we right past a block size?
		else if( (i % KEYLENGTH) == BLOCKSIZE ) {
		SubBytes( temp, 4 ); // Substitute each byte.
		}
		#endif
		
		// Add bytes in GF(2) one KEYLENGTH away.
		XORBytes( temp, expandedKey - KEYLENGTH, 4 );
		
		// Copy result to current 4 bytes.
		*(expandedKey++) = temp[ 0 ];
		*(expandedKey++) = temp[ 1 ];
		*(expandedKey++) = temp[ 2 ];
		*(expandedKey++) = temp[ 3 ];
		
		i += 4; // Next 4 bytes.
	}
}

void InvCipher( unsigned char * block, unsigned char * expandedKey )
{
	unsigned char round = ROUNDS-1;
	expandedKey += BLOCKSIZE * ROUNDS;
	
	XORBytes( block, expandedKey, BLOCKSIZE);
	expandedKey -= BLOCKSIZE;
	
	do {
		InvShiftRows( block );
		InvSubBytesAndXOR( block, expandedKey, BLOCKSIZE);
		expandedKey -= BLOCKSIZE;
		InvMixColumns( block );
	} while( --round );
	
	InvShiftRows( block );
	InvSubBytesAndXOR( block, expandedKey, BLOCKSIZE);
}

void aesDecInit(void)
{
	powTbl = block1;
	logTbl = block2;
	CalcPowLog( powTbl, logTbl );
	
	sBox = tempbuf;
	CalcSBox( sBox );
	
	expandedKey = block1;
	KeyExpansion( expandedKey );
	
	sBoxInv = block2; // Must be block2.
	CalcSBoxInv( sBox, sBoxInv );
}

/*void aesDecrypt( unsigned char * buffer, unsigned char * chainBlock )
{
	unsigned char temp[BLOCKSIZE];
	
	CopyBytes( temp, buffer, BLOCKSIZE );
	InvCipher( buffer, expandedKey );
	XORBytes( buffer, chainBlock, BLOCKSIZE );
	CopyBytes( chainBlock, temp, BLOCKSIZE );
}*/


void aesDecrypt(unsigned char * in,unsigned char * out,unsigned int inlen)
{
	unsigned char temp[BLOCKSIZE];
	unsigned int i=0;
	
	for(i = 0 ; i < inlen ; i +=BLOCKSIZE)
	{
		memcpy(temp , in + i , BLOCKSIZE);
		InvCipher(temp , expandedKey);
		XORBytes((unsigned char *)temp, chainCipherBlock, BLOCKSIZE);
		memcpy(out + i , temp , BLOCKSIZE);
                
	}
}

unsigned char Multiply( unsigned char num, unsigned char factor )
{
	unsigned char mask = 1;
	unsigned char result = 0;
	
	while( mask != 0 ) 
	{
	// Check bit of factor given by mask.
		if( mask & factor ) 
		{
		  // Add current multiple of num in GF(2).
		  result ^= num;
		}
	
		// Shift mask to indicate next bit.
		mask <<= 1;
		
		// Double num.
		num = (num << 1) ^ (num & 0x80 ? BPOLY : 0);
	}
	
	return result;
}

unsigned char DotProduct( unsigned char * vector1, unsigned char * vector2 )
{
	unsigned char result = 0;
	
	result ^= Multiply( *vector1++, *vector2++ );
	result ^= Multiply( *vector1++, *vector2++ );
	result ^= Multiply( *vector1++, *vector2++ );
	result ^= Multiply( *vector1  , *vector2   );
	
	return result;
}

void MixColumn( unsigned char * column )
{
	unsigned char row[8] = {0x02, 0x03, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01}; 
	// Prepare first row of matrix twice, to eliminate need for cycling.
	
	unsigned char result[4];
	
	// Take dot products of each matrix row and the column vector.
	result[0] = DotProduct( row+0, column );
	result[1] = DotProduct( row+3, column );
	result[2] = DotProduct( row+2, column );
	result[3] = DotProduct( row+1, column );
	
	// Copy temporary result to original column.
	column[0] = result[0];
	column[1] = result[1];
	column[2] = result[2];
	column[3] = result[3];
}

void MixColumns( unsigned char * state )
{
	MixColumn( state + 0*4 );
	MixColumn( state + 1*4 );
	MixColumn( state + 2*4 );
	MixColumn( state + 3*4 );
}

void ShiftRows( unsigned char * state )
{
	unsigned char temp;
	
	// Note: State is arranged column by column.
	
	// Cycle second row left one time.
	temp = state[ 1 + 0*4 ];
	state[ 1 + 0*4 ] = state[ 1 + 1*4 ];
	state[ 1 + 1*4 ] = state[ 1 + 2*4 ];
	state[ 1 + 2*4 ] = state[ 1 + 3*4 ];
	state[ 1 + 3*4 ] = temp;
	
	// Cycle third row left two times.
	temp = state[ 2 + 0*4 ];
	state[ 2 + 0*4 ] = state[ 2 + 2*4 ];
	state[ 2 + 2*4 ] = temp;
	temp = state[ 2 + 1*4 ];
	state[ 2 + 1*4 ] = state[ 2 + 3*4 ];
	state[ 2 + 3*4 ] = temp;
	
	// Cycle fourth row left three times, ie. right once.
	temp = state[ 3 + 3*4 ];
	state[ 3 + 3*4 ] = state[ 3 + 2*4 ];
	state[ 3 + 2*4 ] = state[ 3 + 1*4 ];
	state[ 3 + 1*4 ] = state[ 3 + 0*4 ];
	state[ 3 + 0*4 ] = temp;
}

void Cipher( unsigned char * block, unsigned char * expandedKey )
{
	unsigned char round = ROUNDS-1;
	
	XORBytes(block, expandedKey, BLOCKSIZE);
	expandedKey += BLOCKSIZE;
	
	do {
		SubBytes( block, BLOCKSIZE);
		ShiftRows( block );
		MixColumns( block );
		XORBytes( block, expandedKey, BLOCKSIZE);
		expandedKey += BLOCKSIZE;
	} while( --round );
	
	SubBytes(block, BLOCKSIZE);
	ShiftRows(block);
	XORBytes(block, expandedKey, BLOCKSIZE);
}

void aesEncInit(void)
{
	powTbl = block1;   //256
	logTbl = tempbuf;  //256
	CalcPowLog( powTbl, logTbl );  //???????block1  tempbuf?? 
	
	sBox = block2;    //256
	CalcSBox( sBox );  //?????block1  tempbuf?block2??
	
	expandedKey = block1;
	KeyExpansion(expandedKey); //???block1??
        
}

/*void aesEncrypt( unsigned char * buffer, unsigned char * chainBlock )
{
	XORBytes( buffer, chainBlock, BLOCKSIZE );
	Cipher( buffer, expandedKey );
	CopyBytes( chainBlock, buffer, BLOCKSIZE );
}*/


void aesEncrypt(unsigned char * in,unsigned char *out ,unsigned int inlen)
{
	unsigned int i=0;
	unsigned char buffer[BLOCKSIZE];
	for( i = 0 ; i < inlen ; i +=BLOCKSIZE)  //31
	{
		memcpy(buffer , in+i , BLOCKSIZE);
              XORBytes(buffer, chainCipherBlock, BLOCKSIZE);
		Cipher(buffer, expandedKey);
              memcpy(out+i , buffer , BLOCKSIZE);
	}
	
	if(i == inlen)
	{
		if((i%32)==0)
		{
		 memset(buffer , 0x00 , 16) ;
		 XORBytes((unsigned char *)buffer, chainCipherBlock, BLOCKSIZE);
		 Cipher((unsigned char *)buffer,expandedKey);
	   memcpy(out + i,buffer,16);i += 16;
		}
	  memset(buffer , 0x00 , 16) ;
		XORBytes((unsigned char *)buffer, chainCipherBlock, BLOCKSIZE);
		Cipher((unsigned char *)buffer,expandedKey);
  	memcpy(out + i,buffer,16);
	}
	else
	{
		inlen = i - inlen; i -= 16;            //32
		memcpy(buffer,in + i,16 - inlen);
	  memset(&buffer[16 - inlen],0x00,inlen);
		XORBytes((unsigned char *)buffer, chainCipherBlock, BLOCKSIZE);
		Cipher((unsigned char *)buffer,expandedKey);
	  memcpy(out+i,buffer,16);i += 16;
		if(((i%32)!=0)||(i==16))
		{
		 memset(buffer , 0x00 , 16) ;
		 XORBytes((unsigned char *)buffer, chainCipherBlock, BLOCKSIZE);	
		 Cipher((unsigned char *)buffer,expandedKey);
  	 memcpy(out + i,buffer,16);	
		}
	}
        
	
}


void AES_Test(void)
{
	//unsigned char dat[96]="000000000000000000000000000";
	unsigned char out_buffer[80],out_buffer1[96],GPRS_DATBUFF22[600];
        unsigned int i=0;
	unsigned char dat[600]={
//0x85,0xE6,0x39,0x00,0x21,0xB8,0x07,0x2C,0xF2,0xAC,0x6F,0x92,0xB2,0x03,0x6E,0x3D,0x2D,
//0xDB,0x1D,0xBD,0x80,0xF6,0x10,0xDC,0xD9,0x35,0x86,0x9F,0xE3,0x69,0xC8,0x11,0x6D,0x83,
//0x24,
//0x1A,0x68,0x7C,0xAD,0x86,0xF1,0xE7,0x40,0x9D,0xBC,0xD8,0x87,0xC2,0x35,0x1F,0x11,0xBD,
//0xE3,0xE9,0x3C,0x82,0x12,0xBD,0xA8,0x61,0xD4,0x81,0xED,0x7D,0x03,0xB1,0x52,0xB9,0xE7,
//0x8F,0x98,0xAD,0xAF,0x9F,0x3D,0xF9,0xEB,0xCD,0x7D,0x8F,0xDF,0xD2,0x51,0xE8,0x54,0x6E,
//0xC7,0x62,0xB3,0x43,0xD9,0x13,0x01,0x3F,0x57,0xEA,0x0D,0x89,0xE7,0xF4,0x3E,0x2B,0x91,0x17,
//0x7A,0x74,0x06,0x4C,0xAF,0x83,0x70,0xD9,0x2D,0x83,0x72,0x99,0xDB,0x2A,0x60,0x2B,0x8E,
//0x99,0xD3,0x49,0x69,0xC3,0xC9,0x09
          0x3D,0x22,0x20,0xE8,0xDD,0x77,0x00,0xDA,0x9F,0x27,0xB2,0x56,0xCD,0x60,0x2F,0x02,0x62,0x86,0xA7,
          0xBC,0xCE,0x86,0x72,0x01,0xD3,0xB3,0x91,0x2D,0xE4,0x22,0x53,0x4C,0x80,0x88,0x67,
          0x25,0x6B,0xF2,0x39,0x80,0x1B,0x0E,0x3E,0x59,0x72,0x05,0x4D,0x07,0x53,0xC1,0x49,
          0x24,0xA7,0xCA,0xAF,0x93,0x4D,0x94,0x39,0x65,0xA1,0xBE,0x85,0xC5,0x15,0x5B,0xFE,
          0x8C,0x69,0x47,0x26,0xB5,0xCF,0x11,0xEA,0x76,0x0F,0x55,0x81,0x30,0x2E,0xEB,0xE8,
          0x47,0x75,0x04,0xA0,0x2E,0xE5,0x95,0xD6,0xB9,0x84,0x9F,0x30,0xE6,0x1F,0xA6,0xC2,
          0xFC,0x93,0x48,0x5C,0x93,0x6E,0xEF,0xCF,0x16,0xBA,0xBD,0xEC,0xDE,0xFE,0x4A,0xF0,
          0x72,0x69,0xAC,0x6C,0x18,0x74,0xB8,0xFD,0x5A,0x6D,0x49,0x22,0xC6


};

	/*while(i<80)
           dat[i++]=i;*/
	
	/*aesEncInit();//
	aesEncrypt(dat,GPRS_DATBUFF22,0x0B);//*/
	memset(GPRS_DATBUFF22,0x00,sizeof(GPRS_DATBUFF22));
	aesDecInit();//
        //aesDecrypt(out_buffer,out_buffer1,96);//
        aesDecrypt(dat,GPRS_DATBUFF22,0x7A);
        for(i = 0;i < 0x7A;i ++)
          Trace(" %X",GPRS_DATBUFF22[i]);

}

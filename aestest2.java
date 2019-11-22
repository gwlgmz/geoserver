import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class aestest2 {

    private static final int BPOLY = 0x1b;
    private List<Integer> powTbl;
    private List<Integer> logTbl;
    private List<Integer> sBox;
    List<Integer> block1 = new LinkedList<>(Arrays.asList(new Integer[256]));
    List<Integer> block2 = new LinkedList<>(Arrays.asList(new Integer[256]));
    List<Integer> tempbuf = new LinkedList<>(Arrays.asList(new Integer[256]));
    List<Integer> expandedKey;
    List<Integer> sBoxInv;
    private static final int[] AES_Key_Table = {
            0xd0, 0x94, 0x3f, 0x8c, 0x29, 0x76, 0x15, 0xd8,
            0x20, 0x40, 0xe3, 0x27, 0x45, 0xd8, 0x48, 0xad,
            0xea, 0x8b, 0x2a, 0x73, 0x16, 0xe9, 0xb0, 0x49,
            0x45, 0xb3, 0x39, 0x28, 0x0a, 0xc3, 0x28, 0x3c,
    };
    private static final int KEYLENGTH = 32;
    private static final int BLOCKSIZE = 16;
    private static final int ROUNDS = 14;
    private static List<Integer> chainCipherBlock = new LinkedList<>(Arrays.asList(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15));




    void CalcPowLog(List<Integer> powTbl, List<Integer> logTbl)
    {
        int i = 0;
        int t = 1;
        do {
            powTbl.set(i, t);
            logTbl.set(t, i);
            i++;
            t ^= (t << 1) ^ ((t & 0x80)!=0 ? BPOLY : 0);
            t = t & 0xFF;
        }while( t != 1 );
        powTbl.set(255, powTbl.get(0));
    }

    void CalcSBox(List<Integer> sBox)
    {
        int i, rot;
        int temp;
        int result;
        i = 0;
        do {
            if( i > 0 )
            {
                temp = powTbl.get(255 - logTbl.get(i));
            } else {
                temp = 0;
            }
            result = temp ^ 0x63;
            result = result & 0xFF;
            for( rot = 0; rot < 4; rot++ )
            {
                temp = (temp<<1) | (temp>>7);
                temp = temp & 0xFF;
                result ^= temp;
                result = result & 0xFF;
            }
            sBox.set(i, result);
            ++i;
            i = i & 0xFF;
        } while( i != 0 );
    }

    void CalcSBoxInv(List<Integer> sBox, List<Integer> sBoxInv)
    {
        int i = 0;
        int j = 0;
        do {
            do {
                if( sBox.get(j) == i )
                {
                    sBoxInv.set(i, j);
                    j = 255;
                }
                ++j;
                j = j & 0xFF;
            } while( j != 0 );
            ++i;
            i = i & 0xFF;
        } while( i != 0 );
    }

    void CycleLeft(List<Integer> row )
    {
        int temp = row.get(0);
        row.set(0, row.get(1));
        row.set(1, row.get(2));
        row.set(2, row.get(3));
        row.set(3, temp);
    }

    void InvMixColumn(List<Integer> column , int i)
    {
        int r0, r1, r2, r3;

        r0 = column.get(i+1) ^ column.get(i+2) ^ column.get(i+3);
        r1 = column.get(i+0) ^ column.get(i+2) ^ column.get(i+3);
        r2 = column.get(i+0) ^ column.get(i+1) ^ column.get(i+3);
        r3 = column.get(i+0) ^ column.get(i+1) ^ column.get(i+2);

        column.set(i+0, ((column.get(i+0) << 1) & 0xFF) ^ ((column.get(i+0) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+1, ((column.get(i+1) << 1) & 0xFF) ^ ((column.get(i+1) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+2, ((column.get(i+2) << 1) & 0xFF) ^ ((column.get(i+2) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+3, ((column.get(i+3) << 1) & 0xFF) ^ ((column.get(i+3) & 0x80) != 0 ? BPOLY : 0));

        r0 ^= column.get(i+0) ^ column.get(i+1);
        r1 ^= column.get(i+1) ^ column.get(i+2);
        r2 ^= column.get(i+2) ^ column.get(i+3);
        r3 ^= column.get(i+0) ^ column.get(i+3);

        column.set(i+0, ((column.get(i+0) << 1) & 0xFF) ^ ((column.get(i+0) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+1, ((column.get(i+1) << 1) & 0xFF) ^ ((column.get(i+1) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+2, ((column.get(i+2) << 1) & 0xFF) ^ ((column.get(i+2) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+3, ((column.get(i+3) << 1) & 0xFF) ^ ((column.get(i+3) & 0x80) != 0 ? BPOLY : 0));

        r0 ^= column.get(i+0) ^ column.get(i+2);
        r1 ^= column.get(i+1) ^ column.get(i+3);
        r2 ^= column.get(i+0) ^ column.get(i+2);
        r3 ^= column.get(i+1) ^ column.get(i+3);

        column.set(i+0, ((column.get(i+0) << 1) & 0xFF) ^ ((column.get(i+0) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+1, ((column.get(i+1) << 1) & 0xFF) ^ ((column.get(i+1) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+2, ((column.get(i+2) << 1) & 0xFF) ^ ((column.get(i+2) & 0x80) != 0 ? BPOLY : 0));
        column.set(i+3, ((column.get(i+3) << 1) & 0xFF) ^ ((column.get(i+3) & 0x80) != 0 ? BPOLY : 0));

        column.set(i+0, (column.get(i+0) ^ (column.get(i+1) ^ column.get(i+2) ^ column.get(i+3)))& 0xFF);

        r0 ^= column.get(i+0);
        r1 ^= column.get(i+0);
        r2 ^= column.get(i+0);
        r3 ^= column.get(i+0);

        column.set(i+0, r0);
        column.set(i+1, r1);
        column.set(i+2, r2);
        column.set(i+3, r3);
    }

    void SubBytes(List<Integer> bytes, int k, int count)
    {
        int i = k;
        do {
            bytes.set(i, sBox.get(bytes.get(i))); // Substitute every byte in state.
            i++;
            count = count & 0xFF;
            --count;
        } while(count!=0);
    }

    void InvSubBytesAndXOR(List<Integer> bytes, int m, List<Integer> key, int k, int count)
    {
        int i = 0;
        do {
            bytes.set(i+m, block2.get(bytes.get(i+m)) ^ key.get(k+i));
            i++;
            i = i & 0xFF;
            --count;
            count = count & 0xFF;
        } while( count!=0 );
    }

    void InvShiftRows(List<Integer> state)
    {
        int temp;
        temp = state.get(1 + 3*4);
        state.set(1 + 3*4, state.get(1 + 2*4));
        state.set(1 + 2*4, state.get(1 + 1*4));
        state.set(1 + 1*4, state.get(1 + 0*4));
        state.set(1 + 0*4, temp);

        temp = state.get(2 + 0*4);
        state.set(2 + 0*4, state.get(2 + 2*4));
        state.set(2 + 2*4, temp);
        temp = state.get(2 + 1*4);
        state.set(2 + 1*4, state.get(2 + 3*4));
        state.set(2 + 3*4, temp);

        temp = state.get(3 + 0*4);
        state.set(3 + 0*4, state.get(3 + 1*4));
        state.set(3 + 1*4, state.get(3 + 2*4));
        state.set(3 + 2*4, state.get(3 + 3*4));
        state.set(3 + 3*4, temp);
    }

    void InvMixColumns(List<Integer> state)
    {
        InvMixColumn(state, 0*4);
        InvMixColumn(state, 1*4 );
        InvMixColumn(state, 2*4 );
        InvMixColumn(state, 3*4 );
    }

    void XORBytes(List<Integer> bytes1, List<Integer> bytes2, int k, int count )
    {
        int i = 0;
        do {
            bytes1.set(i, bytes1.get(i) ^ bytes2.get(k+i));
            i++;
            --count;
        } while( count!=0 );
    }

    void CopyBytes(List<Integer> to, List<Integer> from, int count )
    {
        int i = 0;
        do {
            to.set(i, from.get(i));
            i++;
            --count;
        } while( count!=0 );
    }

    void KeyExpansion(List<Integer> expandedKey)
    {
        List<Integer> temp = new LinkedList<Integer>(Arrays.asList(new Integer[4]));
        int i;
        List<Integer> Rcon = new LinkedList<Integer>(Arrays.asList(0x01, 0x00, 0x00, 0x00));

        int k=0;

        i = KEYLENGTH;
        do {
            expandedKey.set(k, AES_Key_Table[k]);
            k++;
            --i;
        } while( i!=0 );

        k -= 4;
        temp.set(0, expandedKey.get(k++));
        temp.set(1, expandedKey.get(k++));
        temp.set(2, expandedKey.get(k++));
        temp.set(3, expandedKey.get(k++));

        i = KEYLENGTH;
        while( i < BLOCKSIZE*(ROUNDS+1) ) {
            if ((i % KEYLENGTH) == 0) {
                CycleLeft(temp);
                SubBytes(temp, 0,4);
                XORBytes(temp, Rcon, 0, 4);
                Rcon.set(0, (Rcon.get(0) << 1) ^ ((Rcon.get(0) & 0x80) != 0 ? BPOLY : 0));
            } else if( (i % KEYLENGTH) == BLOCKSIZE ) {
                SubBytes( temp, 0,4 );
            }

            XORBytes(temp, expandedKey, k - KEYLENGTH, 4);

            expandedKey.set(k++, temp.get(0));
            expandedKey.set(k++, temp.get(1));
            expandedKey.set(k++, temp.get(2));
            expandedKey.set(k++, temp.get(3));

            i += 4;
        }
    }

    void InvCipher(List<Integer> block, List<Integer> expandedKey , int k)
    {
        k = k & 0xFF;
        int round = ROUNDS-1;
        k += BLOCKSIZE * ROUNDS;
        k = k & 0xFF;

        XORBytes( block, expandedKey, k, BLOCKSIZE);
        k -= BLOCKSIZE;
        k = k & 0xFF;

        do {
            InvShiftRows( block );
            InvSubBytesAndXOR( block, 0, expandedKey, k, BLOCKSIZE);
            k -= BLOCKSIZE;
            k = k & 0xFF;
            InvMixColumns( block );
            --round;
        } while( round!=0 );

        InvShiftRows( block );
        InvSubBytesAndXOR( block,0, expandedKey, k, BLOCKSIZE);
    }

    void aesDecInit()
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

    void aesDecrypt(List<Integer> in, List<Integer> out, int inlen)
    {
        List<Integer> temp = new LinkedList<Integer>(Arrays.asList(new Integer[BLOCKSIZE]));
        int i=0;

        for(i = 0 ; i < inlen ; i +=BLOCKSIZE)
        {
            memcpy(temp,0, in, i, BLOCKSIZE);
            InvCipher(temp , expandedKey, 0);
            XORBytes(temp, chainCipherBlock,0, BLOCKSIZE);
            memcpy(out, i, temp,0, BLOCKSIZE);

        }
    }

    int Multiply(int num, int factor)
    {
        int mask = 1;
        int result = 0;
        while( mask != 0 ) {
            if( (mask & factor)!=0 ) {
                result ^= num;
                result = result & 0xFF;
            }
            mask <<= 1;
            num = (num << 1) ^ ((num & 0x80)!=0 ? BPOLY : 0);
            num = num & 0xFF;
        }
        return result;
    }

    int DotProduct(List<Integer> vector1, int m, List<Integer> vector2, int k)
    {
        int result = 0;

        result ^= Multiply(vector1.get(m++), vector2.get(k++));
        result ^= Multiply(vector1.get(m++), vector2.get(k++));
        result ^= Multiply(vector1.get(m++), vector2.get(k++));
        result ^= Multiply(vector1.get(m), vector2.get(k));

        return result;
    }

    void MixColumn(List<Integer> column, int k)
    {
        List<Integer> row = new LinkedList<>(Arrays.asList(0x02, 0x03, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01));

        int[] result = new int[4];

        result[0] = DotProduct( row, 0, column, k );
        result[1] = DotProduct( row, 3, column, k );
        result[2] = DotProduct( row, 2, column, k );
        result[3] = DotProduct( row, 1, column, k );

        column.set(0+k, result[0]);
        column.set(1+k, result[1]);
        column.set(2+k, result[2]);
        column.set(3+k, result[3]);
    }

    void MixColumns(List<Integer> state ,int k)
    {
        MixColumn( state, k+0*4 );
        MixColumn( state, k+1*4 );
        MixColumn( state, k+2*4 );
        MixColumn( state, k+3*4 );
    }

    void ShiftRows(List<Integer> state ,int k)
    {
        int temp;

        temp = state.get(1 + 0*4);
        state.set(1 + 0*4, state.get(1 + 1*4));
        state.set(1 + 1*4, state.get(1 + 2*4));
        state.set(1 + 2*4, state.get(1 + 3*4));
        state.set(1 + 3*4, temp);

        temp = state.get(2 + 0*4);
        state.set(2 + 0*4, state.get(2 + 2*4));
        state.set(2 + 2*4, temp);
        temp = state.get(2 + 1*4);
        state.set(2 + 1*4, state.get(2 + 3*4));
        state.set(2 + 3*4, temp);

        temp = state.get(3 + 3*4);
        state.set(3 + 3*4, state.get(3 + 2*4));
        state.set(3 + 2*4, state.get(3 + 1*4));
        state.set(3 + 1*4, state.get(3 + 0*4));
        state.set(3 + 0*4, temp);
    }

    void Cipher(List<Integer> block, int m, List<Integer> expandedKey, int k)
    {
        int round = ROUNDS-1;

        XORBytes(block, expandedKey, k, BLOCKSIZE);
        k += BLOCKSIZE;

        do {
            SubBytes(block, m, BLOCKSIZE);
            ShiftRows(block, m);
            MixColumns(block, m);
            XORBytes(block, expandedKey, k, BLOCKSIZE);
            k += BLOCKSIZE;
            k = k & 0xFF;
            --round;
        } while( round!=0 );

        SubBytes(block, m, BLOCKSIZE);
        ShiftRows(block, m);
        XORBytes(block, expandedKey, k, BLOCKSIZE);
    }

    void aesEncInit()
    {
        powTbl = block1;
        logTbl = tempbuf;
        CalcPowLog( powTbl, logTbl );

        sBox = block2;
        CalcSBox( sBox );

        expandedKey = block1;
        KeyExpansion(expandedKey);

    }

    void aesEncrypt(List<Integer> in, List<Integer> out, int inlen)
    {
        int i=0;
        List<Integer> buffer = new LinkedList<>(Arrays.asList(new Integer[BLOCKSIZE]));
        for( i = 0 ; i < inlen ; i +=BLOCKSIZE)  //31
        {
            memcpy(buffer,0, in, i, BLOCKSIZE);
            XORBytes(buffer, chainCipherBlock, 0, BLOCKSIZE);
            Cipher(buffer, 0, expandedKey, 0);
            memcpy(out, i, buffer, 0, BLOCKSIZE);
        }

        if(i == inlen)
        {
            if((i%32)==0)
            {
                memset(buffer, 0, 0x00, 16) ;
                XORBytes(buffer, chainCipherBlock, 0, BLOCKSIZE);
                Cipher(buffer, 0, expandedKey, 0);
                memcpy(out, i, buffer, 0,16);
                i += 16;
            }
            memset(buffer , 0, 0x00 , 16) ;
            XORBytes(buffer, chainCipherBlock, 0, BLOCKSIZE);
            Cipher(buffer, 0, expandedKey, 0);
            memcpy(out, i, buffer, 0,16);
        }
        else
        {
            inlen = i - inlen; i -= 16;
            memcpy(buffer, 0, in, i,16 - inlen);
            memset(buffer,16-inlen,0x00, inlen);
            XORBytes(buffer, chainCipherBlock, 0, BLOCKSIZE);
            Cipher(buffer, 0, expandedKey, 0);
            memcpy(out, i, buffer, 0,16);
            i += 16;
            if(((i%32)!=0)||(i==16))
            {
                memset(buffer, 0, 0x00, 16) ;
                XORBytes(buffer, chainCipherBlock, 0, BLOCKSIZE);
                Cipher(buffer, 0, expandedKey, 0);
                memcpy(out, i, buffer, 0,16);
            }
        }


    }


    void memcpy(List<Integer> temp, int m, List<Integer> in, int k, int size){
        for (int i = 0; i < size; i++){
            temp.set(m+i, in.get(k+i));
        }
    }

    void memset(List<Integer> temp, int m, int key, int size){

            for (int i = 0; i < size; i++){
                temp.set(m+i, key);
            }

    }

    public static void main(String[] args) {
        aestest2 aes = new aestest2();
        List<Integer> GPRS_DATBUFF22 = new LinkedList<>(Arrays.asList(new Integer[600]));
        int i=0;
        List<Integer> dat = new LinkedList<>(Arrays.asList(0x19,0x03,0x19,0x04,0x30,0x12,0x08,
                0x21,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00));

        aes.memset(GPRS_DATBUFF22, 0, 0x00,600);
//        aes.aesDecInit();//
        aes.aesEncInit();
        //aesDecrypt(out_buffer,out_buffer1,96);//
//        aes.aesDecrypt(dat,GPRS_DATBUFF22,0x7A);
        aes.aesEncrypt(dat,GPRS_DATBUFF22,0x20);
        for(i = 0; i < 0x7A; i++){
            String tmp = (Integer.toHexString(GPRS_DATBUFF22.get(i) & 0XFF));
            if (tmp.length() == 1) {
                tmp =  tmp;
            }
            System.out.print(tmp+" ");
        }


    }

}

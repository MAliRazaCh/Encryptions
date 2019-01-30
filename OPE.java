package encryption;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Hashtable;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class OPE
{
  private static final int BitsForRCoins = 64;
  private static final int BitsForHGDCoins = 128;
  private byte[] key = null;
  private static final int plainTextSpace = 40;
  public static final long MIN_PLAINTEXT = 0L;
  public static final long MAX_PLAINTEXT = 1099511627775L;
  private static final int cipherTextSpace = 48;
  public static final long MIN_CIPHERTEXT = 0L;
  public static final long MAX_CIPHERTEXT = 281474976710646L;
  private Mac VIL_PRF;
  private Hashtable<Long, Long> cache;
  private static final int maxCacheSize = 4000000;
  private boolean DEBUG = false;
  
  public OPE(String strKey)
  {
    this.key = strKey.getBytes();
    this.VIL_PRF = new HMac(new SHA1Digest());
    this.VIL_PRF.init(new KeyParameter(this.key));
    
    this.cache = new Hashtable(4000000);
  }
  
  public long encrypt(long plainNum)
    throws IOException, OPE.HGDException, NoSuchAlgorithmException
  {
    if ((plainNum < 0L) || (plainNum > 1099511627775L))
    {
      if ((plainNum < 0L) || (plainNum > 281474976710646L))
      {
        if (this.DEBUG) {
          System.out.println("OPE cannot encrypt number " + plainNum + " because it is out of the plaintext range. It has been returned without any change.");
        }
        return plainNum;
      }
      throw new IllegalArgumentException("OPE encryption failed: the given plaintext number " + plainNum + " is out of plaintet range [" + 0L + ", " + 1099511627775L + "]");
    }
    long result = EncK(0L, 1099511627775L, 0L, 281474976710646L, plainNum);
    
    return result;
  }
  
  private long EncK(long lowD, long highD, long lowR, long highR, long m)
    throws IOException, OPE.HGDException, NoSuchAlgorithmException
  {
    long M = highD - lowD + 1L;
    long N = highR - lowR + 1L;
    long d = lowD - 1L;
    long r = lowR - 1L;
    long y = r + (N + 1L) / 2L;
    if (M == 1L)
    {
      byte[] coins = TapeGen(lowD, highD, lowR, highR, m, 64);
      SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
      sr.setSeed(coins);
      long result = lowR + (sr.nextLong() & 0x7FFFFFFFFFFFFFFF) % N;
      return result;
    }
    Long x = (Long)this.cache.get(Long.valueOf(y));
    if (x == null)
    {
      byte[] coins = TapeGen(lowD, highD, lowR, highR, y, 128);
      x = Long.valueOf(lowD + HGD(y - lowR, M, N - M, coins));
      if (this.cache.size() > 4000000) {
        this.cache.clear();
      }
      this.cache.put(Long.valueOf(y), x);
    }
    if (m <= x.longValue())
    {
      lowD = d + 1L;
      highD = x.longValue();
      lowR = r + 1L;
      highR = y;
    }
    else
    {
      lowD = x.longValue() + 1L;
      highD = d + M;
      lowR = y + 1L;
      highR = r + N;
    }
    return EncK(lowD, highD, lowR, highR, m);
  }
  
  public long decrypt(long cipherNum)
    throws IOException, OPE.HGDException, NoSuchAlgorithmException
  {
    if ((cipherNum < 0L) || (cipherNum > 281474976710646L))
    {
      if (this.DEBUG) {
        System.out.println("OPE cannot decrypt number " + cipherNum + " because it is out of the ciphertext range. It has been returned without any change.");
      }
      return cipherNum;
    }
    long result = DecK(0L, 1099511627775L, 0L, 281474976710646L, cipherNum);
    
    return result;
  }
  
  private long DecK(long lowD, long highD, long lowR, long highR, long c)
    throws IOException, OPE.HGDException, NoSuchAlgorithmException
  {
    long M = highD - lowD + 1L;
    long N = highR - lowR + 1L;
    long d = lowD - 1L;
    long r = lowR - 1L;
    long y = r + (N + 1L) / 2L;
    if (M == 1L)
    {
      long m = lowD;
      byte[] coins = TapeGen(lowD, highD, lowR, highR, m, 64);
      SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
      sr.setSeed(coins);
      long w = lowR + (sr.nextLong() & 0x7FFFFFFFFFFFFFFF) % N;
      if (w == c) {
        return m;
      }
      System.out.println(String.format("This value %d was not encrypted correctly", new Object[] {
        Long.valueOf(c) }));
      throw new IllegalArgumentException();
    }
    Long x = (Long)this.cache.get(Long.valueOf(y));
    if (x == null)
    {
      byte[] coins = TapeGen(lowD, highD, lowR, highR, y, 128);
      x = Long.valueOf(lowD + HGD(y - lowR, M, N - M, coins));
      if (this.cache.size() > 4000000) {
        this.cache.clear();
      }
      this.cache.put(Long.valueOf(y), x);
    }
    if (c <= y)
    {
      lowD = d + 1L;
      highD = x.longValue();
      lowR = r + 1L;
      highR = y;
    }
    else
    {
      lowD = x.longValue() + 1L;
      highD = d + M;
      lowR = y + 1L;
      highR = r + N;
    }
    return DecK(lowD, highD, lowR, highR, c);
  }
  
  private byte[] TapeGen(long lowD, long highD, long lowR, long highR, long m, int numOfBits)
    throws IOException, NoSuchAlgorithmException
  {
    int numOfBytes = (numOfBits + 7) / 8;
    
    byte[] input = longsToBytes(new long[] { lowD, highD, lowR, highR, m });
    byte[] seed = new byte[this.VIL_PRF.getMacSize()];
    synchronized (this.VIL_PRF)
    {
      this.VIL_PRF.update(input, 0, input.length);
      this.VIL_PRF.doFinal(seed, 0);
    }
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(seed);
    byte[] coins = new byte[numOfBytes];
    sr.nextBytes(coins);
    if (numOfBytes % 8 != 0)
    {
      int tmp143_142 = 0; byte[] tmp143_140 = coins;tmp143_140[tmp143_142] = ((byte)(tmp143_140[tmp143_142] & (65280 >> 8 - numOfBytes % 8 ^ 0xFFFFFFFF)));
    }
    return coins;
  }
  
  public long HGD(long KK, long NN1, long NN2, byte[] coins)
    throws OPE.HGDException, NoSuchAlgorithmException
  {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(coins);
    
    double IX = 0.0D;
    
    double CON = 57.56462733D;
    double DELTAL = 0.0078D;
    double DELTAU = 0.0034D;
    double SCALE = 1.0E25D;
    if ((NN1 < 0L) || (NN2 < 0L) || (KK < 0L) || (KK > NN1 + NN2))
    {
      System.out.println("Invalid parameters for HGD NN1: " + NN1 + ", NN2: " + NN2 + ", KK: " + KK);
      
      throw new IllegalArgumentException();
    }
    boolean REJECT = true;
    double N2;
    double N1;
    double N2;
    if (NN1 >= NN2)
    {
      double N1 = NN2;
      N2 = NN1;
    }
    else
    {
      N1 = NN1;
      N2 = NN2;
    }
    double TN = N1 + N2;
    double K;
    double K;
    if (KK + KK >= TN) {
      K = TN - KK;
    } else {
      K = KK;
    }
    double M = (K + 1.0D) * (N1 + 1.0D) / (TN + 2.0D);
    double MINJX;
    double MINJX;
    if (K - N2 < 0.0D) {
      MINJX = 0.0D;
    } else {
      MINJX = K - N2;
    }
    double MAXJX;
    double MAXJX;
    if (N1 < K) {
      MAXJX = N1;
    } else {
      MAXJX = K;
    }
    if (MINJX == MAXJX)
    {
      IX = MINJX;
    }
    else if (M - MINJX < 10.0D)
    {
      double W;
      double W;
      if (K < N2) {
        W = Math.exp(CON + AFC(N2) + AFC(N1 + N2 - K) - AFC(N2 - K) - 
          AFC(N1 + N2));
      } else {
        W = Math.exp(CON + AFC(N1) + AFC(K) - AFC(K - N2) - 
          AFC(N1 + N2));
      }
      boolean flagTen = true;
      boolean flagTwenty = true;
      int countFlagTen = 0;int countFlagTwenty = 0;
      for (; flagTen; goto 456)
      {
        countFlagTen++;
        if ((countFlagTen % 500 == 0) && 
          (this.DEBUG)) {
          System.out.println("passed through label ten " + countFlagTen + " times");
        }
        flagTen = false;
        double P = W;
        IX = MINJX;
        double U = sr.nextDouble() * SCALE;
        countFlagTwenty = 0;
        while ((flagTwenty) && (!flagTen))
        {
          countFlagTwenty++;
          if (countFlagTwenty > 1000)
          {
            System.out.println("Time out in Inverse Transfromation");
            throw new HGDException();
          }
          flagTwenty = false;
          if (U > P)
          {
            U -= P;
            P = P * (N1 - IX) * (K - IX);
            IX += 1.0D;
            P = P / IX / (N2 - K + IX);
            if (IX > MAXJX) {
              flagTen = true;
            }
            flagTwenty = true;
          }
        }
      }
      if (this.DEBUG) {
        System.out.println("Inverse Transfromation: MINJX: " + MINJX + ", MAXJX: " + MAXJX + ", IX: " + IX);
      }
    }
    else
    {
      double S = Math.sqrt((TN - K) * K * N1 * N2 / (TN - 1.0D) / TN / TN);
      double D = Math.floor(1.5D * S) + 0.5D;
      double XL = Math.floor(M - D + 0.5D);
      double XR = Math.floor(M + D + 0.5D);
      double A = AFC(M) + AFC(N1 - M) + AFC(K - M) + AFC(N2 - K + M);
      double KL = Math.exp(A - AFC(XL) - AFC(N1 - XL) - AFC(K - XL) - 
        AFC(N2 - K + XL));
      double KR = Math.exp(A - AFC(XR - 1.0D) - AFC(N1 - XR + 1.0D) - AFC(K - XR + 1.0D) - 
        AFC(N2 - K + XR - 1.0D));
      
      double LAMDL = -Math.log(XL * (N2 - K + XL) / (N1 - XL + 1.0D) / (K - XL + 1.0D));
      
      double LAMDR = -Math.log((N1 - XR + 1.0D) * (K - XR + 1.0D) / XR / (N2 - K + XR));
      double P1 = 2.0D * D;
      double P2 = P1 + KL / LAMDL;
      double P3 = P2 + KR / LAMDR;
      
      int countThirtyB = 0;
      while (REJECT)
      {
        countThirtyB++;
        if ((countThirtyB % 500 == 0) && 
          (this.DEBUG)) {
          System.out.println("In H2PE, count is " + countThirtyB);
        }
        double U = sr.nextDouble() * P3;
        double V = sr.nextDouble();
        if (U < P1)
        {
          IX = XL + U;
        }
        else if (U <= P2)
        {
          IX = XL + Math.log(V) / LAMDL;
          if (IX < MINJX)
          {
            if (!this.DEBUG) {
              continue;
            }
            System.out.println("left. \n"); continue;
          }
          V = V * (U - P1) * LAMDL;
        }
        else
        {
          IX = XR - Math.log(V) / LAMDR;
          if (IX > MAXJX)
          {
            if (!this.DEBUG) {
              continue;
            }
            System.out.println("right. \n"); continue;
          }
          V = V * (U - P2) * LAMDR;
        }
        if ((M < 100.0D) || (IX <= 50.0D))
        {
          double F = 1.0D;
          if (M < IX) {
            for (double I = M + 1.0D; I < IX; I += 1.0D) {
              F = F * (N1 - I + 1.0D) * (K - I + 1.0D) / (N2 - K + I) / I;
            }
          } else if (M > IX) {
            for (double I = IX + 1.0D; I < M; I += 1.0D) {
              F = F * I * (N2 - K + I) / (N1 - I) / (K - I);
            }
          }
          if (V <= F) {
            REJECT = false;
          }
        }
        else
        {
          double Y = IX;
          double Y1 = Y + 1.0D;
          double YM = Y - M;
          double YN = N1 - Y + 1.0D;
          double YK = K - Y + 1.0D;
          double NK = N2 - K + Y1;
          double R = -YM / Y1;
          double S2 = YM / YN;
          double T = YM / YK;
          double E = -YM / NK;
          double G = YN * YK / (Y1 * NK) - 1.0D;
          double DG = 1.0D;
          if (G < 0.0D) {
            DG = 1.0D + G;
          }
          double GU = G * (1.0D + G * (-0.5D + G / 3.0D));
          double GL = GU - 0.25D * Math.pow(G, 4.0D) / DG;
          double XM = M + 0.5D;
          double XN = N1 - M + 0.5D;
          double XK = K - M + 0.5D;
          double NM = N2 - K + XM;
          double UB = Y * GU - M * GL + DELTAU + XM * R * (1.0D + R * (-0.5D + R / 3.0D)) + XN * S2 * (1.0D + S2 * (-0.5D + S2 / 3.0D)) + XK * T * (1.0D + T * (-0.5D + T / 3.0D)) + NM * E * (1.0D + E * (-0.5D + E / 3.0D));
          
          double ALV = Math.log(V);
          if (ALV > UB)
          {
            REJECT = true;
          }
          else
          {
            double DR = XM * Math.pow(R, 4.0D);
            if (R < 0.0D) {
              DR /= (1.0D + R);
            }
            double DS = XN * Math.pow(S2, 4.0D);
            if (S2 < 0.0D) {
              DS /= (1.0D + S2);
            }
            double DT = XK * Math.pow(T, 4.0D);
            if (T < 0.0D) {
              DT /= (1.0D + T);
            }
            double DE = NM * Math.pow(E, 4.0D);
            if (E < 0.0D) {
              DE /= (1.0D + E);
            }
            if (ALV < UB - 0.25D * (DR + DS + DT + DE) + (Y + M) * (GL - GU) - DELTAL) {
              REJECT = false;
            } else if (ALV <= A - AFC(IX) - AFC(N1 - IX) - AFC(K - IX) - AFC(N2 - K + IX)) {
              REJECT = false;
            } else {
              REJECT = true;
            }
          }
        }
      }
    }
    if (KK + KK >= TN)
    {
      if (NN1 > NN2) {
        IX = KK - NN2 + IX;
      } else {
        IX = NN1 - IX;
      }
    }
    else if (NN1 > NN2) {
      IX = KK - IX;
    }
    double JX = IX;
    if (this.DEBUG) {
      System.out.println("KK: " + KK + ", NN1: " + NN1 + ", NN2: " + NN2 + "HGD Sample value: " + JX);
    }
    return (JX + 0.5D);
  }
  
  private double AFC(double I)
  {
    double[] AL = { 0.0D, 0.0D, 0.6931471806D, 1.791759469D, 3.17805383D, 4.787491743D, 6.579251212D, 8.525161361D };
    if (I <= 7.0D) {
      return AL[((int)Math.round(I))];
    }
    double LL = Math.log(I);
    return (I + 0.5D) * LL - I + 0.399089934D;
  }
  
  private byte[] longsToBytes(long[] values)
    throws IOException
  {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    for (int i = 0; i < values.length; i++) {
      dos.writeLong(values[i]);
    }
    return baos.toByteArray();
  }
  
  public Long encrypt(Long objectToEncrypt, String key)
  {
    try
    {
      return Long.valueOf(encrypt(objectToEncrypt.longValue()));
    }
    catch (NoSuchAlgorithmException|IOException|HGDException e)
    {
      System.out.println("Order preserving encryption failed");
      e.printStackTrace();
      System.exit(1);
    }
    return Long.valueOf(-1L);
  }
  
  public Long decrypt(Long objectToDecrypt, String key)
  {
    try
    {
      return Long.valueOf(decrypt(objectToDecrypt.longValue()));
    }
    catch (NoSuchAlgorithmException|IOException|HGDException e)
    {
      System.out.println("Order preserving decrption failed");
      e.printStackTrace();
      System.exit(1);
    }
    return Long.valueOf(-1L);
  }
  
  class HGDException
    extends Exception
  {
    HGDException() {}
  }
}

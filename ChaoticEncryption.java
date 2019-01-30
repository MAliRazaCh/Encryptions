package encryption;

import java.io.PrintStream;

public class ChaoticEncryption
{
  private boolean initialized = false;
  private byte[] key;
  private int blocksize;
  double x0_Sine;
  
  public ChaoticEncryption(String secrtKey, int keySize)
  {
    this.initialized = false;
    if (secrtKey == null) {
      throw new SecurityException("Chaotic encryption has been selected, but no key was found.");
    }
    try
    {
      this.blocksize = (keySize / 8);
      byte[] ktemp = secrtKey.getBytes();
      
      byte[] k = new byte[this.blocksize];
      for (int i = 0; i < this.blocksize; i++) {
        k[i] = ktemp[i];
      }
      byte[] t = toLogisticBytes(0.4000005D, 0.734375D, keySize);
      byte[] l = toTentBytes(0.4000005D, 0.734375D, keySize);
      byte[] s = toSineBytes(0.4000005D, 0.734375D, keySize);
      
      this.key = new byte[this.blocksize];
      for (int i = 0; i < this.key.length; i++) {
        this.key[i] = ((byte)(k[i] ^ t[i] ^ l[i] ^ s[i]));
      }
    }
    catch (Exception e)
    {
      System.out.println("Cannot initialize Chaotic encryption with current key. Assure the key is a BASE64 - 128 oe 256 bits long" + e);
    }
    this.initialized = true;
  }
  
  public byte[] encryptOrDecrypt(int mode, byte[] input, int offset, int length)
    throws Exception
  {
    int len = input.length;
    int counter = 0;
    byte[] content = new byte[len];
    for (int i = 0; i < len; i++)
    {
      if (counter >= this.blocksize) {
        counter = 0;
      }
      content[i] = ((byte)(this.key[counter] ^ input[i]));
      counter++;
    }
    return content;
  }
  
  public byte[] encrypt(byte[] content)
    throws Exception
  {
    return encryptOrDecrypt(1, content, 0, content.length);
  }
  
  public byte[] decrypt(byte[] content)
    throws Exception
  {
    return encryptOrDecrypt(2, content, 0, content.length);
  }
  
  double Lambda_Sine = 3.99D;
  double x0_Tent;
  double Lambda_Tent = 0.4D;
  double x0_Logistic;
  double Lambda_Logistic = 3.99D;
  
  public int toSineByte()
  {
    try
    {
      int currentByte = 0;
      double X1 = 0.0D;
      for (int i = 0; i < 8; i++)
      {
        X1 = this.Lambda_Sine * Math.sin(3.141592653589793D * this.x0_Sine);
        currentByte = currentByte << 1 | (X1 >= 0.5D ? 1 : 0);
        this.x0_Sine = X1;
      }
      return currentByte;
    }
    catch (Exception localException) {}
    return -1;
  }
  
  public byte[] toSineBytes(double x0, double Lambda, int size)
  {
    this.x0_Sine = x0;
    this.Lambda_Sine = Lambda;
    
    byte[] out = new byte[this.blocksize];
    for (int i = 0; i < this.blocksize; i++) {
      out[i] = ((byte)(toSineByte() & 0xFF));
    }
    return out;
  }
  
  public int toTentByte()
  {
    try
    {
      int currentByte = 0;
      double X1 = 0.0D;
      for (int i = 0; i < 8; i++)
      {
        if (this.x0_Tent <= this.Lambda_Tent) {
          X1 = this.x0_Tent / this.Lambda_Tent;
        } else {
          X1 = (1.0D - this.x0_Tent) / (1.0D - this.Lambda_Tent);
        }
        currentByte = currentByte << 1 | (X1 >= 0.5D ? 1 : 0);
        this.x0_Tent = X1;
      }
      return currentByte;
    }
    catch (Exception localException) {}
    return -1;
  }
  
  public byte[] toTentBytes(double x0, double Lambda, int size)
  {
    this.x0_Tent = x0;
    this.Lambda_Tent = Lambda;
    
    byte[] out = new byte[this.blocksize];
    for (int i = 0; i < this.blocksize; i++) {
      out[i] = ((byte)(toTentByte() & 0xFF));
    }
    return out;
  }
  
  public int toLogisticByte()
  {
    try
    {
      int currentByte = 0;
      double X1 = 0.0D;
      for (int i = 0; i < 8; i++)
      {
        X1 = this.Lambda_Logistic * this.x0_Logistic * (1.0D - this.x0_Logistic);
        currentByte = currentByte << 1 | (X1 >= 0.5D ? 1 : 0);
        this.x0_Logistic = X1;
      }
      return currentByte;
    }
    catch (Exception localException) {}
    return -1;
  }
  
  public byte[] toLogisticBytes(double x0, double Lambda, int size)
  {
    this.x0_Logistic = x0;
    this.Lambda_Logistic = Lambda;
    
    byte[] out = new byte[this.blocksize];
    for (int i = 0; i < this.blocksize; i++) {
      out[i] = ((byte)(toLogisticByte() & 0xFF));
    }
    return out;
  }
}

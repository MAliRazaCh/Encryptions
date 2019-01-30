package encryption;

import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryption
{
  private final String ALGORITHM_NAME = "AES";
  private SecretKeySpec theKey;
  private Cipher cipher;
  private boolean initialized = false;
  
  public AESEncryption(String secrtKey, int keySize)
  {
    this.initialized = false;
    if (secrtKey == null) {
      throw new SecurityException("AES encryption has been selected, but no key was found. Please configure it by passing the key as property at database create/open. The property key is: '" + secrtKey + "'");
    }
    try
    {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      KeySpec spec = new PBEKeySpec(secrtKey.toCharArray(), secrtKey.getBytes(), 128, keySize);
      SecretKey tmp = skf.generateSecret(spec);
      this.theKey = new SecretKeySpec(tmp.getEncoded(), "AES");
      
      this.cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
    catch (NoSuchAlgorithmException|InvalidKeySpecException|NoSuchPaddingException e)
    {
      System.out.println("Cannot initialize AES encryption with current key. Assure the key is a BASE64 - 128 or 256 bits long" + e);
    }
    this.initialized = true;
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
  
  public byte[] encryptOrDecrypt(int mode, byte[] input, int offset, int length)
    throws Exception
  {
    if (!this.initialized) {
      throw new SecurityException("AES encryption algorithm is not available");
    }
    this.cipher.init(mode, this.theKey);
    byte[] content;
    byte[] content;
    if ((offset == 0) && (length == input.length))
    {
      content = input;
    }
    else
    {
      content = new byte[length];
      System.arraycopy(input, offset, content, 0, length);
    }
    return this.cipher.doFinal(content);
  }
}

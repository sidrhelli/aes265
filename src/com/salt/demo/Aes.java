package com.salt.demo;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes {
  private static final String ALGORITHM = "AES";
  private static final String AES_CBC_PADDING = "AES/CBC/PKCS5Padding";
  private static final int IV_SIZE = 16;
  private static final byte[] AES_KEY =
      {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
  private static final SecretKeySpec secret = new SecretKeySpec(AES_KEY, ALGORITHM);

  private Aes() {}

  public static String encrypt(String plainText) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);

    SecureRandom secureRandom = new SecureRandom();
    byte[] iv = new byte[IV_SIZE];
    secureRandom.nextBytes(iv);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);

    byte[] cipherText = cipher.doFinal(plainText.getBytes());
    byte[] cipherTextWithIvPrefix = new byte[iv.length + cipherText.length];

    System.arraycopy(iv, 0, cipherTextWithIvPrefix, 0, iv.length);
    System.arraycopy(cipherText, 0, cipherTextWithIvPrefix, iv.length, cipherText.length);

    return new String(new String(Base64.getEncoder().encode(cipherTextWithIvPrefix), StandardCharsets.UTF_8)); // basencodeTostring standard encodes to ISO-8859-1
  }

  public static String decrypt(String cipherText) throws Exception {
    Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);

    byte[] ivBytes = Arrays.copyOfRange(cipherText.getBytes(), 0, IV_SIZE);
    IvParameterSpec ivParamsSpec = new IvParameterSpec(ivBytes);
    cipher.init(Cipher.DECRYPT_MODE, secret, ivParamsSpec);

    byte[] base64decodedCipherText = Base64.getDecoder().decode(cipherText.getBytes());
    byte[] decryptedCipherText = cipher.doFinal(base64decodedCipherText);
    byte[] originalCipherTextWithoutIv = Arrays.copyOfRange(decryptedCipherText, IV_SIZE, decryptedCipherText.length);

    return new String(originalCipherTextWithoutIv, StandardCharsets.UTF_8);
  }



}

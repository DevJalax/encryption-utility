import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AESEncryptionUtility {
	public static final String secretKeys = "AbRaKaDabRa";
	private static SecretKeySpec secretKey;
	private static byte[] key;

	public static String decrypt(String strToDecrypt, String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			log.info("==================================Decrypt");
			String password = new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
			log.info("==================================Decrypt --{}", password);
			return password;
		} catch (Exception e) {
			log.info("ERROR==================================Decrypt --{}", e);
			log.error("error :{}", e);
		}
		return null;
	}

	public static String encrypt(String strToEncrypt, String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		} catch (Exception e) {
			log.error("error :{}", e);
		}
		return null;
	}

	public static void setKey(String myKey) {
		MessageDigest sha = null;
		try {
			key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			log.error("error :{}", e);
		} catch (UnsupportedEncodingException e) {
			log.error("error :{}", e);
		}
	}
}

package zw.chinapnr;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

public class Keys {

	/**
	 * 初始化密钥
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ZwContextDefine.KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(ZwContextDefine.PUBLIC_KEY, publicKey);
		keyMap.put(ZwContextDefine.PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	/**
	 * 初始化密钥
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey(Integer keySize) throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ZwContextDefine.KEY_ALGORITHM);
		keyPairGen.initialize(keySize);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(ZwContextDefine.PUBLIC_KEY, publicKey);
		keyMap.put(ZwContextDefine.PRIVATE_KEY, privateKey);
		return keyMap;
	}
	
	public static String getPublicKey(Map<String, Object> keyMap)
			throws Exception {
		Key key = (Key) keyMap.get(ZwContextDefine.PUBLIC_KEY);
		return ZwBase64.encryptToString(key.getEncoded());

	}

	public static String getPrivateKey(Map<String, Object> keyMap)
			throws Exception {
		Key key = (Key) keyMap.get(ZwContextDefine.PRIVATE_KEY);
		return ZwBase64.encryptToString(key.getEncoded());
	}
}
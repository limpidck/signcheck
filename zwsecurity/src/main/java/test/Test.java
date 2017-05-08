package test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Random;

import zw.chinapnr.Keys;
import zw.chinapnr.RSACoder;
import zw.chinapnr.SecureLink;
import zw.chinapnr.ZwBase64;

public class Test {
	public static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKARXJSi1SINOXIqwb6bUuvrRQlf41qML7yqH79zUn/Q3+zBziZlDgYzop3xZf6QOPDx7rZL2dD7SLSGeUd906Lv0Ddlp5lRwN7TjQZNww0OY7cxiiKLoakVanOdkPJbajwmljBJqoZ6heMaQYdHm2YqsIQjqJ5gJOgP1tIon8dDAgMBAAECgYAYolNjNKQkd3CN13K1yOW8FRss1CsDNmvqVyxHpJHfxd+Qaks1sXu1DKFMOWh/AucgfbtFJutAtEt+LOvhSsYVILpBOIJ1lTioHuiuoTDTv6COWRliUbH3QAx9h4O9VEzPQF1BiU7FUWL5DMNZAmCC/je9jI8C/ayr3k+iOfcJ8QJBAOCWndK5VB0UBb2kxl7UjFkQgeybjltCrzOJT03bzP6dxBRnKYRWm9Kk/suaBf7GVqpb9cO+UTfRw98xUo6FxU0CQQC2dJacOoPBIavdyxKN1cHThYPpG5HtjyBpUqjaxGeBmUKWW9pjprIm7pY9Ynj3Xn4/o5nJ8iFhzCxJiH+2szbPAkEAgC32TXpww1fWHvKYNS9iGsMNJBl0GinpDKTlmi5ExV0NuAdY7qrvrD13HoT9vvc8J2bs0Zchi5YxEIV59NXsUQJAH2dRxPINW2CARFx/hQoVomKIocatB0ZrPbWMeprzdcr7OwX0QNKgNzM5iLc6Otl4wVtXTPrv4/VQahekY73U4QJAAksAyZWbk45DJyxO3IrJkdamaD2OxoIyt8I+pBioN4itf/afBr7IZTizPEwfOzXyiTYMHfv2X9F9KARzlnRNQw=="; 
	public static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgEVyUotUiDTlyKsG+m1Lr60UJX+NajC+8qh+/c1J/0N/swc4mZQ4GM6Kd8WX+kDjw8e62S9nQ+0i0hnlHfdOi79A3ZaeZUcDe040GTcMNDmO3MYoii6GpFWpznZDyW2o8JpYwSaqGeoXjGkGHR5tmKrCEI6ieYCToD9bSKJ/HQwIDAQAB";
	
	public static void main(String[] args) throws Exception{
		Test test = new Test();
		String rootPath = test.getClass().getResource("/").getPath();
		
		InputStream pubKeyIs = null;
	    InputStream priKeyIs = null;
	 
	     pubKeyIs = new FileInputStream((rootPath+"zwkeys/zw_public_key.pem"));
	     priKeyIs = new FileInputStream((rootPath+"zwkeys/zw_private_key.pem"));
	    
	     //知屋公私钥
//	     pubKeyIs = new FileInputStream("G:/allkeys/zwkeys/zw_public_key.pem");
//	     priKeyIs = new FileInputStream("G:/allkeys/zwkeys/zw_private_key.pem");
	     
	     //商户公私钥
//	     pubKeyIs = new FileInputStream("G:/allkeys/shkeys/sh_public_key.pem");
//	     priKeyIs = new FileInputStream("G:/allkeys/shkeys/sh_private_key.pem");
	     
	     publicKey = SecureLink.loadKeyContent(pubKeyIs);   
	     privateKey = SecureLink.loadKeyContent(priKeyIs);   
		try {
			//generateKeysString();
			//enAndDeSignByString(publicKey, privateKey);
			//enAndDeSignByFileStream(pubKeyIs, priKeyIs);
			enAndDePass(publicKey, privateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public void showURL() throws IOException {

        // 第一种：获取类加载的根路径   
        File f = new File(this.getClass().getResource("/").getPath());
        System.out.println(f);

        // 获取当前类的所在工程路径; 如果不加“/” 
        File f2 = new File(this.getClass().getResource("").getPath());
        System.out.println(f2);

        // 第二种：获取项目路径  
        File directory = new File("");// 参数为空
        String courseFile = directory.getCanonicalPath();
        System.out.println(courseFile);
    }
	
	
	public static void enAndDeSignByFileStream(InputStream publicKey,InputStream privateKey) throws Exception{
		// 需要加签的字符串
		String toAssignStr = getDesignSizeStr(20);
		System.out.println("需要加密的字符串：" + toAssignStr);
		
		// 私钥对加密数据进行签名
		String s = SecureLink.sign(toAssignStr.getBytes(), privateKey);
		System.out.println("私钥对数据的签名为：" + s);
		
		// 公钥对加密数据进行验签
		boolean verflag = SecureLink.verify(toAssignStr.getBytes(), publicKey, s);
		System.out.println("公钥对数据的验签结果：" + verflag);
	}
	
	public static void enAndDeSignByString(String publicKey,String privateKey) throws Exception{
		// 需要加签的字符串
		String toAssignStr = getDesignSizeStr(20);
		System.out.println("需要加密的字符串：" + toAssignStr);
					
		// 私钥对加密数据进行签名
		String s = SecureLink.sign(toAssignStr.getBytes(), privateKey);
		System.out.println("私钥对数据的签名为：" + s);

		// 公钥对加密数据进行验签
		boolean verflag = SecureLink.verify(toAssignStr.getBytes(), publicKey, s);
		System.out.println("公钥对数据的验签结果：" + verflag);
	}
	
	public static void enAndDePass(String publicKey,String privateKey) throws Exception{
		// 然后利用公钥进行加密
		String str = getDesignSizeStr(117);
		System.out.println("公钥需要加密的字符串：" + str);
		
		byte[] pks = RSACoder.encryptByPublicKey(str.getBytes(), publicKey);
		String pkss = ZwBase64.encryptToString(pks);
		System.out.println("公钥加密后的数据：" + pkss);

		// 然后私钥进行解密
		byte[] sks = RSACoder.decryptByPrivateKey(pks, privateKey);
		String skss = new String(sks);
		System.out.println("私钥解密后的数据：" + skss);
		
		// 私钥重新加密
		String strNew = getDesignSizeStr(117);
		System.out.println("私钥需要加密的字符串：" + strNew);

		byte[] newsks = RSACoder.encryptByPrivateKey(strNew.getBytes(), privateKey);
		String newskss = ZwBase64.encryptToString(newsks);
		System.out.println("私钥加密后的数据：" + newskss);

		// 公钥对数据进行解密
		byte[] newpks = RSACoder.decryptByPublicKey(newsks, publicKey);
		String newpkss = new String(newpks);
		System.out.println("公钥对私钥数据解密：" + newpkss);
	}
	
	public static void generateKeysString() throws Exception{
		// 生成公私钥对
		//Map<String, Object> map = Keys.initKey();
		
		// 生成公私钥对 +size
		Map<String, Object> map = Keys.initKey(2048);
		// 使用BASE64对公私钥对进行加密
		String pk = Keys.getPublicKey(map);
		String sk = Keys.getPrivateKey(map);

		System.out.println("获取公钥:"+pk);
		System.out.println("获取私钥:"+sk);
	}
	
	public static String getDesignSizeStr(int size){
        String encryptStr= "";  
        String[] radomStrArray = new String[]{"a","b","c","d","e","f","g","h","i","g","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","1","2","3","4","5","6","7","8","9","0"};
        for (int i = 0; i < size; i++) {
        	encryptStr = encryptStr +   radomStrArray[new Random().nextInt(radomStrArray.length)];
		}
        System.out.println("当前获取的字符串长度为："+encryptStr.length()+"--字节数为："+getByteLengthByStr(encryptStr));
        return encryptStr;
	}
	
	public static int getByteLengthByStr(String str){
		byte[] buff=str.getBytes();
		int length=buff.length;
		return length;
	}
}

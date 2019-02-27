package Token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author 给我丶鼓励
 */
public class TokenUtils {

    /**
     * 1.创建一个32-byte的密匙
     */

    private static final byte[] secret = "geiwodiangasfdjsikolkjikolkijswe".getBytes();


    //生成一个token
    public static String creatTokenHS256(Map<String,Object> payloadMap) throws JOSEException {

        //3.先建立一个头部Header
        /**
         * JWSHeader参数：1.加密算法法则,2.类型，3.。。。。。。。
         * 一般只需要传入加密算法法则就可以。
         * 这里则采用HS256
         *
         * JWSAlgorithm类里面有所有的加密算法法则，直接调用。
         */
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

        //建立一个载荷Payload
        Payload payload = new Payload(new JSONObject(payloadMap));

        //将头部和载荷结合在一起
        JWSObject jwsObject = new JWSObject(jwsHeader, payload);

        //建立一个密匙

        JWSSigner jwsSigner = new MACSigner(secret);

        //签名
        jwsObject.sign(jwsSigner);

        //生成token
        return jwsObject.serialize();



    }
    //解析token
    public static Map<String,Object> validHS256(String token) throws ParseException, JOSEException {
//        解析token
        JWSObject jwsObject = JWSObject.parse(token);
        //建立一个解锁密匙
        JWSVerifier jwsVerifier = new MACVerifier(secret);
        return verify(jwsObject, jwsVerifier);
    }


    //验证token信息
    private static Map<String,Object> verify(JWSObject jwsObject,JWSVerifier jwsVerifier) throws JOSEException {
        Map<String, Object> resultMap = new HashMap<>();
        //获取到载荷
        Payload payload=jwsObject.getPayload();
        //判断token
        if (jwsObject.verify(jwsVerifier)) {
            resultMap.put("Result", 0);
            //载荷的数据解析成json对象。
            JSONObject jsonObject = payload.toJSONObject();
            resultMap.put("data", jsonObject);
            //判断token是否过期
            if (jsonObject.containsKey("exp")) {
                Long expTime = Long.valueOf(jsonObject.get("exp").toString());
                Long nowTime = new Date().getTime();
                //判断是否过期
                if (nowTime > expTime) {
                    //已经过期
                    resultMap.clear();
                    resultMap.put("Result", 2);
                }
            }
        }else {
            resultMap.put("Result", 1);
        }
        return resultMap;
    }

    /**
     * 创建加密key
     */
    public static RSAKey getKey() throws JOSEException {
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        RSAKey rsaJWK = rsaKeyGenerator.generate();
        return rsaJWK;
    }

    //进行token加密
    public static String creatTokenRS256(Map<String,Object> payloadMap,RSAKey rsaJWK) throws JOSEException {

        //私密钥匙
        JWSSigner signer = new RSASSASigner(rsaJWK);

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaJWK.getKeyID()).build(),
                new Payload(new JSONObject(payloadMap))
        );
        //进行加密
        jwsObject.sign(signer);

        String token= jwsObject.serialize();
        return token;
    }

    //验证token
    public static Map<String,Object> validRS256(String token,RSAKey rsaJWK) throws ParseException, JOSEException {
        //获取到公钥
        RSAKey rsaKey = rsaJWK.toPublicJWK();
        JWSObject jwsObject = JWSObject.parse(token);
        JWSVerifier jwsVerifier = new RSASSAVerifier(rsaKey);
        //验证数据
        return verify(jwsObject, jwsVerifier);
    }
}

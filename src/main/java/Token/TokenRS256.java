package Token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenRS256 {

    /**
     * 这个方法采取的是RS256 非对称加密算法
     */

    public static String TokenTest(String uid,RSAKey rsaJWK) {
        //获取生成token
        Map<String, Object> map = new HashMap<>();
        Date date = new Date();

        //建立载荷，这些数据根据业务，自己定义。
        map.put("uid", uid);
        //生成时间
        map.put("sta", date.getTime());
        //过期时间
        map.put("exp", date.getTime()+6000);
        try {
            String token = TokenUtils.creatTokenRS256(map,rsaJWK);
            return token;
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return null;
    }

    //处理解析的业务逻辑
    public static void ValidToken(String token,RSAKey rsaJWK) {
        //解析token
        try {
            if (token != null) {
                Map<String, Object> validMap = TokenUtils.validRS256(token,rsaJWK);
                int i = (int) validMap.get("Result");
                if (i == 0) {
                    System.out.println("token解析成功");
                    JSONObject jsonObject = (JSONObject) validMap.get("data");
                    System.out.println("uid是：" + jsonObject.get("uid")+" sta是："+jsonObject.get("sta")+" exp是："+jsonObject.get("exp"));
                } else if (i == 2) {
                    System.out.println("token已经过期");
                }
            }
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws JOSEException {
        //获取token
        String uid = "rs256 test";
        //获取钥匙
        RSAKey key = TokenUtils.getKey();
        //获取token
        String token = TokenTest(uid,key);
        System.out.println("非对称加密的token："+token);
        //解析token
        ValidToken(token,key);
    }


}

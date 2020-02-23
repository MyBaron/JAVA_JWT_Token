package token.jwt;

/**
 * @author: baron
 * @date: 2020-01-13 23:32
 **/
public class TestHS256 {

    public static void main(String[] args) throws InterruptedException {
        TestHS256 t = new TestHS256();
        t.testHS256();
    }

    //测试HS256加密生成Token
    public void testHS256() throws InterruptedException {
        String token = JWTHS256.buildJWT("account123");
        //解密token
        String account = JWTHS256.vaildToken(token);
        System.out.println("校验token成功，token的账号："+account);

        //测试过期
        System.out.println("测试token过期------");
        Thread.sleep(10 * 1000);
        account = JWTHS256.vaildToken(token);
        System.out.println(account);
    }
}

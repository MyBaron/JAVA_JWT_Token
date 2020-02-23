package token.jwt;

/**
 * @author: baron
 * @date: 2020-01-13 23:32
 **/
public class TestRS256 {

    public static void main(String[] args) throws InterruptedException {
        TestRS256 t = new TestRS256();
        t.testRS256();
    }

    //测试RS256加密生成Token
    public void testRS256() throws InterruptedException {
        String token = JWTRSA256.buildToken("account123");
        //解密token
        String account = JWTRSA256.volidToken(token);
        System.out.println("校验token成功，token的账号："+account);

        //测试过期
        System.out.println("测试token过期------");
        Thread.sleep(10 * 1000);
        account = JWTRSA256.volidToken(token);
        System.out.println(account);
    }
}

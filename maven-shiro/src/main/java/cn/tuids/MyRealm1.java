package cn.tuids;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

/**
 * @author tuids
 * @date 2024/1/4 23:46
 */
public class MyRealm1 implements Realm {
    @Override
    public String getName() {
        return "MyRealm1";
    }

    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户名和密码
        String username = (String) token.getPrincipal();
        String password = new String((char[]) token.getCredentials());
        // 用户名错误 => 未知账户异常
        if (!"tuids".equals(username)) {
            throw new UnknownAccountException();
        }
        // 密码错误 => 凭证错误异常
        if ("123".equals(password)) {
            throw new IncorrectCredentialsException();
        }
        // 认证成功,返回一个AuthenticationInfo的实现
        return new SimpleAuthenticationInfo(username,password,getName());
    }
}

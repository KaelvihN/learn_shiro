package cn.tuids;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Assert;
import org.junit.jupiter.api.Test;

import java.util.Optional;

/**
 * @author tuids
 * @date 2024/1/4 0:30
 */
public class ShiroApp {
    static Logger logger;

    static {
        BasicConfigurator.configure();
        logger = Logger.getLogger(ShiroApp.class);

    }

    @Test
    public void test() {
        login("classpath:shiro-authenticator-all-success.ini");
        // 获取验证成功的subject
        Subject subject = SecurityUtils.getSubject();
        //得到一个身份集合，其包含了Realm验证成功的身份信息
        PrincipalCollection principals = subject.getPrincipals();
        System.out.println("principals = " + principals);

    }

    private void login(String configFile) {
        // 创建SecurityManger工厂，此处使用Ini文件充当数据源来初始化SecurityManger
        IniSecurityManagerFactory securityManagerFactory = new IniSecurityManagerFactory(configFile);
        //创建对象实例，并绑定给SecurityUtils
        SecurityManager securityManager = securityManagerFactory.createInstance();
        SecurityUtils.setSecurityManager(securityManager);
        //得到Subject，创建username/password 验证 token
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("tuids", "123");
        try {
            //登录验证身份
            subject.login(token);
            logger.info("登录成功," + subject.isAuthenticated());
        } catch (AuthenticationException e) {
            //登录失败
            logger.error("登录失败,失败原因:" + e);
        }
    }
}
